use std::array;
use std::fmt;
use std::fmt::Display;
use std::result::Result::{Err, Ok};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadMutInPlace, KeyInit},
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use bytes::{BufMut, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret as ECDHPrivate, PublicKey as ECDHPublic};

use crate::transport::{Address, Controller, Stream};

type PrivateKey = [u8; 32];
type PublicKey = [u8; 32];
type RandomKey = [u8; 32];
type Secret = [u8; 32];
type NonceB = [u8; 12];

/*
2 byte header fields looks like:

[2bit msg type ] [ 14 bit msg length ]
[            msg data                ]
*/
const HANDSHAKE: u8 = 0b11000000;
const CONNECT: u8 = 0b10000000;
const DATA: u8 = 0b01000000;
#[allow(dead_code)]
const PING: u8 = 0b00000000;
const MSG_TYPE_FLAG: u8 = 0b11000000;
const DATA_SIZE_HIGH_FLAG: u8 = 0b00111111;
const MAX_MSG_SIZE: usize = 0b00111111_11111111;
const HEADER_SIZE: usize = 2;
const MAX_RECORD_SIZE: usize = MAX_MSG_SIZE + HEADER_SIZE;

fn extract_msg_header(high: u8, low: u8) -> (u8, usize) {
    (
        high & MSG_TYPE_FLAG,
        u16::from_be_bytes([high & DATA_SIZE_HIGH_FLAG, low]) as usize,
    )
}

async fn read_msg(stream: &mut Stream) -> Result<(u8, BytesMut)> {
    let mut buf = bytes::BytesMut::with_capacity(256);
    let typ = read_msg_inplace(stream, &mut buf).await?;
    Ok((typ, buf))
}

async fn read_msg_inplace(stream: &mut Stream, buf: &mut BytesMut) -> Result<u8> {
    let mut header = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .with_context(|| "Failed to read msg header from stream")?;
    let (msg_type, body_size) = extract_msg_header(header[0], header[1]);
    buf.resize(body_size, 0);
    if buf.len() == 0 {
        return Ok(msg_type);
    }
    stream
        .read_exact(buf)
        .await
        .with_context(|| "Failed to read msg body from stream")?;
    Ok(msg_type)
}

fn start_msg(msg_type: u8, body_size: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(body_size + HEADER_SIZE);
    start_msg_inplace(msg_type, body_size, &mut buf);
    buf
}

fn start_msg_inplace(msg_type: u8, body_size: usize, buf: &mut BytesMut) {
    assert!(body_size <= MAX_MSG_SIZE);
    assert!(msg_type >= DATA);
    buf.resize(0, 0);
    let high = (body_size >> 8) as u8;
    let low = (body_size & 0xff) as u8;
    buf.put_u8(high | msg_type);
    buf.put_u8(low);
}

pub struct ClientHello(BytesMut);

impl ClientHello {
    const SIZE: usize = 128;
    const HANDSHAKE_MSG_SIZE: usize = Self::SIZE + HEADER_SIZE;

    fn get_public_key<'a>(&'a self) -> &'a PublicKey {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        buf[0..32].try_into().unwrap()
    }
    fn get_random_key<'a>(&'a self) -> &'a RandomKey {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        buf[32..64].try_into().unwrap()
    }

    fn get_verify_part<'a>(&'a self) -> &'a [u8] {
        &self.as_ref()[..64]
    }

    fn get_signature<'a>(&'a self) -> Signature {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        Signature::from_slice(&buf[64..128]).unwrap()
    }

    fn build_msg(
        ephemeral_public: &PublicKey,
        random: &RandomKey,
        signer: &SigningKey,
    ) -> Result<BytesMut> {
        let mut buf = start_msg(HANDSHAKE, Self::SIZE);
        buf.put_slice(ephemeral_public);
        buf.put_slice(random);
        let signature = signer
            .try_sign(&buf[HEADER_SIZE..])
            .with_context(|| "Failed to sign client hello")?;
        buf.put_slice(signature.r_bytes());
        buf.put_slice(signature.s_bytes());
        assert!(
            buf.len() == Self::HANDSHAKE_MSG_SIZE,
            "{} != {}",
            buf.len(),
            Self::HANDSHAKE_MSG_SIZE
        );
        Ok(buf)
    }

    fn parse(buf: BytesMut, verifier: &VerifyingKey) -> Result<Self> {
        if buf.len() != Self::SIZE {
            return Err(anyhow!("Invalid client hello msg length: {}", buf.len()));
        }
        let hello = Self(buf);
        let signature = hello.get_signature();
        verifier
            .verify_strict(hello.get_verify_part(), &signature)
            .with_context(|| "Failed to verify client hello signature")?;
        Ok(hello)
    }
}

impl Into<ClientHello> for BytesMut {
    fn into(self) -> ClientHello {
        ClientHello(self)
    }
}

impl AsRef<[u8]> for ClientHello {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct ServerHello(BytesMut);

impl ServerHello {
    const SIZE: usize = 128;
    fn get_public_key<'a>(&'a self) -> &'a PublicKey {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        buf[0..32].try_into().unwrap()
    }
    fn get_random_key<'a>(&'a self) -> &'a RandomKey {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        buf[32..64].try_into().unwrap()
    }

    fn get_verify_part<'a>(&'a self) -> &'a [u8] {
        &self.as_ref()[..64]
    }

    fn get_signature<'a>(&'a self) -> Signature {
        let buf = self.as_ref();
        assert!(buf.len() == Self::SIZE);
        Signature::from_slice(&buf[64..128]).unwrap()
    }

    fn build_msg(public: &PublicKey, random: &RandomKey, signer: &SigningKey) -> Result<BytesMut> {
        let mut buf = start_msg(HANDSHAKE, Self::SIZE);
        buf.put_slice(public);
        buf.put_slice(random);
        let signature = signer
            .try_sign(buf[HEADER_SIZE..].as_ref())
            .with_context(|| "Failed to sign")?;
        buf.put_slice(signature.r_bytes());
        buf.put_slice(signature.s_bytes());
        assert!(buf.len() == Self::SIZE + HEADER_SIZE);
        Ok(buf)
    }

    fn parse(buf: BytesMut, verifier: &VerifyingKey) -> Result<Self> {
        if buf.len() != Self::SIZE {
            return Err(anyhow!("Invalid server hello msg length: {}", buf.len()));
        }
        let hello = Self(buf);
        let signature = hello.get_signature();
        verifier
            .verify_strict(hello.get_verify_part(), &signature)
            .with_context(|| "Failed to verify server hello signature")?;
        Ok(hello)
    }
}

impl Into<ServerHello> for BytesMut {
    fn into(self) -> ServerHello {
        ServerHello(self)
    }
}

impl AsRef<[u8]> for ServerHello {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn generate_random() -> Result<RandomKey> {
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(random.as_mut())
        .with_context(|| "Failed to generate random bytes")?;
    Ok(random)
}

pub async fn client_handshake(
    stream: &mut Stream,
    singer: &SigningKey,
    verifier: &VerifyingKey,
) -> anyhow::Result<(Session, Session)> {
    let ephemeral_private = ECDHPrivate::random();
    let ephemeral_public = ECDHPublic::from(&ephemeral_private);
    let client_random = generate_random()?;

    let client_hello = ClientHello::build_msg(ephemeral_public.as_bytes(), &client_random, singer)?;
    stream
        .write_all(&client_hello)
        .await
        .with_context(|| "Failed to write to stream")?;
    let mut hash = Sha256::new();
    hash.update(&client_hello[HEADER_SIZE..]);

    let (msg_type, buf) = read_msg(stream).await?;
    if msg_type != HANDSHAKE {
        return Err(anyhow!("Invalid message type: {}", msg_type));
    }
    let serve_hello = &ServerHello::parse(buf, verifier)?;
    hash.update(serve_hello);
    let hello_hash = hash.finalize();
    let their_public = ECDHPublic::from(serve_hello.get_public_key().clone());
    let shared_key = ephemeral_private.diffie_hellman(&their_public);

    let (client_secret_iv, client_secret, server_secret_iv, server_secret) = expand_secret(
        &client_random,
        serve_hello.get_random_key(),
        shared_key.as_bytes(),
        &hello_hash,
    );

    Ok((
        Session::new(
            stream.clone(),
            client_secret_iv,
            Aes256Gcm::new(&client_secret.into()),
        ),
        Session::new(
            stream.clone(),
            server_secret_iv,
            Aes256Gcm::new(&server_secret.into()),
        ),
    ))
}

pub async fn server_handshake(
    stream: &mut Stream,
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> anyhow::Result<(Session, Session)> {
    let ecdh_private = ECDHPrivate::random();
    let ecdh_public = ECDHPublic::from(&ecdh_private);
    let server_random = generate_random()?;
    let (msg_type, msg) = read_msg(stream).await?;
    if msg_type != HANDSHAKE {
        return Err(anyhow!("Invalid message type: {}", msg_type));
    }
    let client_hello = &ClientHello::parse(msg, verifier)?;
    let mut hash = Sha256::new();
    hash.update(client_hello);

    let server_hello = ServerHello::build_msg(ecdh_public.as_bytes(), &server_random, signer)?;
    stream
        .write_all(&server_hello)
        .await
        .with_context(|| "Failed to write to stream")?;
    hash.update(&server_hello[HEADER_SIZE..]);

    let hello_hash = hash.finalize();
    let their_public = ECDHPublic::from(client_hello.get_public_key().clone());
    let shared_key = ecdh_private.diffie_hellman(&their_public);

    let (client_secret_iv, client_secret, server_secret_iv, server_secret) = expand_secret(
        client_hello.get_random_key(),
        &server_random,
        shared_key.as_bytes(),
        &hello_hash,
    );

    Ok((
        Session::new(
            stream.clone(),
            client_secret_iv,
            Aes256Gcm::new(&client_secret.into()),
        ),
        Session::new(
            stream.clone(),
            server_secret_iv,
            Aes256Gcm::new(&server_secret.into()),
        ),
    ))
}

pub async fn copy_encrypted_bidirectional(
    controller: Controller,
    read_half: &mut Session,
    write_half: &mut Session,
    raw_stream: &mut Stream,
) -> (usize, usize) {
    let _guard = controller.relay_guard();
    let mut raw_reader = raw_stream.clone();
    tokio::join!(
        read_half.relay_encrypt_to_plain_forever(controller.clone(), raw_stream),
        write_half.relay_plain_to_encrypt_forever(controller.clone(), &mut raw_reader),
    )
}

struct Seq([u8; 12]);

impl Seq {
    pub fn incr(&mut self) {
        for i in 11..0 {
            self.0[i] += 1;
            if self.0[i] != 0 {
                return;
            }
        }
        panic!("Sequence overflow");
    }
    pub fn xor_secret_iv(&self, secret_iv: &NonceB) -> NonceB {
        array::from_fn(|i| self.0[i] ^ secret_iv[i])
    }
}

impl AsRef<[u8; 12]> for Seq {
    fn as_ref(&self) -> &[u8; 12] {
        &self.0
    }
}

pub struct Session {
    stream: Stream,
    secret_iv: NonceB,
    sequence: Seq,
    aead: Aes256Gcm,
    raw_buf: BytesMut,
    buf: BytesMut,
}

impl Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Session({})", self.stream)
    }
}

impl Session {
    pub fn new(stream: Stream, secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            stream,
            secret_iv,
            sequence: Seq([0; 12]),
            aead,
            raw_buf: BytesMut::with_capacity(MAX_RECORD_SIZE),
            buf: BytesMut::with_capacity(MAX_RECORD_SIZE),
        }
    }

    pub async fn relay_encrypt_to_plain_forever(
        &mut self,
        controller: Controller,
        writer: &mut Stream,
    ) -> usize {
        let mut size: usize = 0;
        loop {
            tokio::select! {
                _ = async move {
                    loop {
                            match self.relay_encrypt_to_plain(writer).await  {
                                Ok(n) => {
                                    size += n;
                                }
                                Err(_) => {
                                    return size;
                                }
                            };
                    }
                } => {
                    return size;
                }
                _ = controller.wait_shutdown() => {
                    return size;
                }
            }
        }
    }

    async fn read_msg_inner(&mut self) -> Result<u8> {
        let typ = read_msg_inplace(&mut self.stream, &mut self.raw_buf).await?;
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        self.buf.resize(self.raw_buf.len(), 0);
        self.aead
            .decrypt_in_place(&nonce.into(), &self.raw_buf, &mut self.buf)
            .with_context(|| "Failed to decrypt message")?;
        self.sequence.incr();
        Ok(typ)
    }

    async fn read_specific_msg_inner(&mut self, expect_type: u8) -> Result<()> {
        let typ = self.read_msg_inner().await?;
        if typ != expect_type {
            return Err(anyhow!(
                "Unexpected message type: {} != {}",
                typ,
                expect_type
            ));
        }
        Ok(())
    }

    pub async fn read_connect_msg(&mut self) -> Result<Address> {
        self.read_specific_msg_inner(CONNECT).await?;
        let addr = Address::from_bytes(&self.raw_buf)?;
        Ok(addr)
    }

    pub async fn write_connect_msg(&mut self, address: Address) -> Result<()> {
        self.raw_buf.put_slice(address.as_string().as_bytes());
        self.write_raw_buf(CONNECT).await
    }

    async fn relay_encrypt_to_plain(&mut self, writer: &mut Stream) -> Result<usize> {
        self.read_specific_msg_inner(DATA).await?;
        writer
            .write_all(&self.raw_buf)
            .await
            .with_context(|| "Failed to write to stream")?;
        Ok(self.raw_buf.len())
    }

    pub async fn relay_plain_to_encrypt_forever(
        &mut self,
        controller: Controller,
        reader: &mut Stream,
    ) -> usize {
        let mut size: usize = 0;
        loop {
            tokio::select! {
                _ = async move {
                    loop {
                            match self.replay_plain_to_encrypt(reader).await  {
                                Ok(n) => {
                                    size += n;
                                }
                                Err(_) => {
                                    return size;
                                }
                            };
                    }
                } => {
                    return size;
                }
                _ = controller.wait_shutdown() => {
                    return size;
                }
            }
        }
    }

    async fn write_raw_buf(&mut self, msg_type: u8) -> Result<()> {
        start_msg_inplace(msg_type, self.raw_buf.len(), &mut self.buf);
        let mut body = self.buf.split_off(HEADER_SIZE);
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        self.aead
            .encrypt_in_place(&nonce.into(), &self.raw_buf, &mut body)
            .with_context(|| "Failed to encrypt message")?;
        self.stream
            .write_all(&self.buf)
            .await
            .with_context(|| "Failed to write to stream")?;
        Ok(())
    }

    async fn replay_plain_to_encrypt(&mut self, reader: &mut Stream) -> Result<usize> {
        self.raw_buf.resize(MAX_MSG_SIZE, 0);
        let n = reader
            .read(&mut self.raw_buf)
            .await
            .with_context(|| "Failed to read message from stream")?;
        self.raw_buf.resize(n, 0);
        self.write_raw_buf(DATA).await?;
        Ok(self.raw_buf.len())
    }
}

const CLIENT_IV_LABEL: &[u8] = b"client_iv";
const SERVER_IV_LABEL: &[u8] = b"server_iv";
const CLIENT_HANDSHAKE_LABEL: &[u8] = b"client_handshake";
const SERVER_HANDSHAKE_LABEL: &[u8] = b"server_handshake";
const CLIENT_LABEL: &[u8] = b"client_traffic";
const SERVER_LABEL: &[u8] = b"server_traffic";

fn expand_secret(
    client_random: &RandomKey,
    server_random: &RandomKey,
    shared_key: &[u8],
    hello_hash: &[u8],
) -> (NonceB, Secret, NonceB, Secret) {
    let early = Hkdf::<Sha256>::new(None, shared_key);
    let mut client_handshake_secret = Secret::default();
    let mut server_handshake_secret = Secret::default();
    early
        .expand_multi_info(
            &[hello_hash, CLIENT_HANDSHAKE_LABEL],
            &mut client_handshake_secret,
        )
        .expect("Failed to expand client handshake");
    early
        .expand_multi_info(
            &[hello_hash, SERVER_HANDSHAKE_LABEL],
            &mut server_handshake_secret,
        )
        .expect("Failed to expand server handshake");

    let client_handshake = Hkdf::<Sha256>::new(Some(client_random), &client_handshake_secret);
    let server_handshake = Hkdf::<Sha256>::new(Some(server_random), &server_handshake_secret);

    let mut client_secret_iv = NonceB::default();
    let mut server_secret_iv = NonceB::default();
    client_handshake
        .expand_multi_info(&[CLIENT_IV_LABEL], &mut client_secret_iv)
        .expect("Fail to expand client iv");
    client_handshake
        .expand_multi_info(&[SERVER_IV_LABEL], &mut server_secret_iv)
        .expect("Fail to expand server iv");

    let mut client_secret = Secret::default();
    let mut server_secret = Secret::default();
    server_handshake
        .expand_multi_info(&[CLIENT_LABEL], &mut client_secret)
        .expect("Fail to expand client app secret");
    server_handshake
        .expand_multi_info(&[SERVER_LABEL], &mut server_secret)
        .expect("Fail to expand server app secret");
    (
        client_secret_iv,
        client_secret,
        server_secret_iv,
        server_secret,
    )
}

pub struct KeyPair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

pub fn decode_signing_key<T: AsRef<[u8]>>(data: T) -> Result<SigningKey> {
    let data = base64.decode(data).context("Failed to decode key")?;
    let b = vec_to_array(data).context("Failed to decode key")?;
    Ok(SigningKey::from_bytes(&b))
}

pub fn decode_verifying_key<T: AsRef<[u8]>>(data: T) -> Result<VerifyingKey> {
    let data = base64.decode(data).context("Failed to decode key")?;
    let b = vec_to_array(data).context("Failed to decode key")?;
    VerifyingKey::from_bytes(&b).context("Failed to decode key")
}

impl KeyPair {
    pub fn random() -> Self {
        let mut rng = OsRng;
        let private_key = SigningKey::generate(&mut rng);
        let public_key = VerifyingKey::from(&private_key);

        KeyPair {
            private: private_key.to_bytes(),
            public: public_key.to_bytes(),
        }
    }
    pub fn print(&self) {
        print!(
            "private_key = \"{}\"\npublic_key = \"{}\"\n",
            self.private_key(),
            self.public_key(),
        )
    }
    pub fn private_key(&self) -> String {
        base64.encode(self.private)
    }
    pub fn public_key(&self) -> String {
        base64.encode(self.public)
    }

    pub fn signer(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private)
    }
    pub fn verifier(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.public).unwrap()
    }
}

fn vec_to_array<const N: usize>(v: Vec<u8>) -> anyhow::Result<[u8; N]> {
    let r = v.try_into();
    match r {
        Ok(a) => Ok(a),
        Err(e) => Err(anyhow::anyhow!(
            "key length is mismatch: expect {} got {}",
            N,
            e.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generate() {
        let secret = KeyPair::random();
        secret.print();
        assert_eq!(32, secret.private.len());
        assert_eq!(32, secret.public.len());
        let parsed_private = decode_signing_key(secret.private_key()).unwrap();
        let parsed_public = decode_verifying_key(secret.public_key()).unwrap();
        assert_eq!(&secret.private, parsed_private.as_bytes());
        assert_eq!(&secret.public, parsed_public.as_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = KeyPair::random();
        secret.print();
        let signer = secret.signer();
        let verifier = secret.verifier();
        let message = b"Hello world";
        let signature = signer.sign(message);
        assert!(verifier.verify_strict(message, &signature).is_ok());
    }

    #[test]
    fn test_client_hello_build_and_parse() {
        let secret = KeyPair::random();
        let random = generate_random().unwrap();
        let hello = ClientHello::build_msg(&secret.public, &random, &secret.signer()).unwrap();
        let (_, body) = hello.split_at(HEADER_SIZE);
        let client_hello = ClientHello::parse(body.into(), &secret.verifier()).unwrap();
        assert_eq!(&secret.public, client_hello.get_public_key());
        assert_eq!(&random, client_hello.get_random_key());
    }

    #[test]
    fn test_server_hello_build_and_parse() {
        let secret = KeyPair::random();
        let random = generate_random().unwrap();
        let hello = ServerHello::build_msg(&secret.public, &random, &secret.signer()).unwrap();
        let (_, body) = hello.split_at(HEADER_SIZE);
        let client_hello = ServerHello::parse(body.into(), &secret.verifier()).unwrap();
        assert_eq!(&secret.public, client_hello.get_public_key());
        assert_eq!(&random, client_hello.get_random_key());
    }

    use ntest::timeout;
    use tokio;
    use tokio::net::{TcpListener, TcpStream};

    async fn build_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        let stream1 = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        println!("Connected: {}", stream1.local_addr().unwrap());
        let stream2 = listener.accept().await.unwrap().0;
        println!("Accepted: {}", stream2.peer_addr().unwrap());
        (stream1, stream2)
    }

    #[tokio::test]
    #[timeout(2000)]
    async fn test_handshake() {
        let client_key = KeyPair::random();
        let server_key = KeyPair::random();

        let (client, server) = build_stream_pair().await;
        let client = &mut Stream::from_tcp_stream(client);
        let server = &mut Stream::from_tcp_stream(server);

        let client_singer = &client_key.signer();
        let client_verifier = &server_key.verifier();
        let server_singer = &server_key.signer();
        let server_verifier = &client_key.verifier();
        tokio::join!(
            async move {
                client_handshake(client, client_singer, client_verifier)
                    .await
                    .unwrap();
            },
            async move {
                server_handshake(server, server_singer, server_verifier)
                    .await
                    .unwrap();
            }
        );
    }
}
