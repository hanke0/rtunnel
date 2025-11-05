use core::fmt;
use std::array;
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

use crate::transport::{Address, Controller, Reader, Writer};

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

fn extract_msg_header(high: u8, low: u8) -> (u8, usize) {
    (
        high & MSG_TYPE_FLAG,
        u16::from_be_bytes([high & DATA_SIZE_HIGH_FLAG, low]) as usize,
    )
}

fn fill_msg_header(msg_type: u8, body_size: usize, buf: &mut BytesMut) {
    let high = (body_size >> 8) as u8;
    let low = (body_size & 0xff) as u8;
    assert!(buf.len() > 1);
    buf[0] = high | msg_type;
    buf[1] = low;
}

async fn read_msg(reader: &mut Reader) -> Result<(u8, BytesMut)> {
    let mut buf = bytes::BytesMut::with_capacity(256);
    let typ = read_msg_inplace(reader, &mut buf).await?;
    Ok((typ, buf))
}

async fn read_msg_inplace(stream: &mut Reader, buf: &mut BytesMut) -> Result<u8> {
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
    mut reader: Reader,
    mut writer: Writer,
    singer: &SigningKey,
    verifier: &VerifyingKey,
) -> anyhow::Result<(ReadSession, WriteSession)> {
    let ephemeral_private = ECDHPrivate::random();
    let ephemeral_public = ECDHPublic::from(&ephemeral_private);
    let client_random = generate_random()?;

    let client_hello = ClientHello::build_msg(ephemeral_public.as_bytes(), &client_random, singer)?;
    writer
        .write_all(&client_hello)
        .await
        .with_context(|| "Failed to write to stream")?;
    let mut hash = Sha256::new();
    hash.update(&client_hello[HEADER_SIZE..]);

    let (msg_type, buf) = read_msg(&mut reader).await?;
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
        ReadSession::new(
            reader,
            client_secret_iv,
            Aes256Gcm::new(&client_secret.into()),
        ),
        WriteSession::new(
            writer,
            server_secret_iv,
            Aes256Gcm::new(&server_secret.into()),
        ),
    ))
}

pub async fn server_handshake(
    mut reader: Reader,
    mut writer: Writer,
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> anyhow::Result<(ReadSession, WriteSession)> {
    let ecdh_private = ECDHPrivate::random();
    let ecdh_public = ECDHPublic::from(&ecdh_private);
    let server_random = generate_random()?;
    let (msg_type, msg) = read_msg(&mut reader).await?;
    if msg_type != HANDSHAKE {
        return Err(anyhow!("Invalid message type: {}", msg_type));
    }
    let client_hello = &ClientHello::parse(msg, verifier)?;
    let mut hash = Sha256::new();
    hash.update(client_hello);

    let server_hello = ServerHello::build_msg(ecdh_public.as_bytes(), &server_random, signer)?;
    writer
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
        ReadSession::new(
            reader,
            client_secret_iv,
            Aes256Gcm::new(&client_secret.into()),
        ),
        WriteSession::new(
            writer,
            server_secret_iv,
            Aes256Gcm::new(&server_secret.into()),
        ),
    ))
}

pub async fn copy_encrypted_bidirectional(
    controller: Controller,
    read_half: &mut ReadSession,
    write_half: &mut WriteSession,
    raw_reader: &mut Reader,
    raw_writer: &mut Writer,
) -> (usize, usize) {
    let _guard = controller.relay_guard();
    tokio::join!(
        read_half.relay_encrypted_to_plain_forever(controller.clone(), raw_writer),
        write_half.relay_plain_to_encrypted_forever(controller.clone(), raw_reader),
    )
}

struct Seq([u8; 12]);

impl Seq {
    pub fn incr(&mut self) {
        let mut i = 11;
        loop {
            self.0[i] += 1;
            if self.0[i] != 0 {
                return;
            }
            if i == 0 {
                panic!("Sequence overflow: {:?}", self.0);
            }
            i -= 1;
        }
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

struct Encryption {
    secret_iv: NonceB,
    sequence: Seq,
    aead: Aes256Gcm,
    encrypted_buf: BytesMut,
}

impl Encryption {
    pub fn new(secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            secret_iv,
            sequence: Seq([0; 12]),
            aead,
            encrypted_buf: BytesMut::with_capacity(1024),
        }
    }

    async fn read_msg(&mut self, reader: &mut Reader, buf: &mut BytesMut) -> Result<u8> {
        self.encrypted_buf.clear();
        let typ = read_msg_inplace(reader, &mut self.encrypted_buf).await?;
        self.decrypt_in_place(buf)?;
        Ok(typ)
    }

    fn decrypt_in_place(&mut self, buf: &mut BytesMut) -> Result<()> {
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        self.aead
            .decrypt_in_place(&nonce.into(), &self.encrypted_buf, buf)
            .with_context(|| "Failed to decrypt message")?;
        self.sequence.incr();
        Ok(())
    }

    fn encrypt_message_in_place(&mut self, msg_type: u8, body: &[u8]) -> Result<()> {
        self.encrypted_buf.resize(HEADER_SIZE, 0);
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        let mut payload = self.encrypted_buf.split_off(self.encrypted_buf.len());
        self.aead
            .encrypt_in_place(&nonce.into(), body, &mut payload)
            .with_context(|| "Failed to encrypt message")?;
        let body_size = payload.len();
        self.encrypted_buf.unsplit(payload);
        fill_msg_header(msg_type, body_size, &mut self.encrypted_buf);
        assert_eq!(extract_msg_header(self.encrypted_buf[0], self.encrypted_buf[1]), (msg_type, body_size));
        self.sequence.incr();
        Ok(())
    }

    async fn read_specific_msg(
        &mut self,
        reader: &mut Reader,
        expect_type: u8,
        buf: &mut BytesMut,
    ) -> Result<()> {
        let typ = self.read_msg(reader, buf).await?;
        if typ != expect_type {
            return Err(anyhow!(
                "Unexpected message type: {} != {}",
                typ,
                expect_type
            ));
        }
        Ok(())
    }

    async fn write_message(
        &mut self,
        writer: &mut Writer,
        msg_type: u8,
        body: &[u8],
    ) -> Result<()> {
        self.encrypt_message_in_place(msg_type, body)?;
        writer
            .write_all(&self.encrypted_buf)
            .await
            .with_context(|| "Failed to write to stream")?;
        self.sequence.incr();
        Ok(())
    }
}

pub struct ReadSession {
    reader: Reader,
    encryption: Encryption,
}

impl ReadSession {
    pub fn new(reader: Reader, secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            reader,
            encryption: Encryption::new(secret_iv, aead),
        }
    }

    pub async fn read_connect_msg(&mut self) -> Result<Address> {
        let buf = &mut BytesMut::with_capacity(32);
        self.encryption
            .read_specific_msg(&mut self.reader, CONNECT, buf)
            .await?;
        let addr = Address::from_bytes(buf)?;
        Ok(addr)
    }

    #[inline]
    #[allow(dead_code)]
    pub async fn read_msg(&mut self, buf: &mut BytesMut) -> Result<u8> {
        self.encryption.read_msg(&mut self.reader, buf).await
    }

    pub async fn relay_encrypted_to_plain_forever(
        &mut self,
        controller: Controller,
        writer: &mut Writer,
    ) -> usize {
        let mut size: usize = 0;
        let buf = &mut BytesMut::with_capacity(1024);
        loop {
            buf.clear();
            tokio::select! {
                _ = async move {
                    loop {
                            match self.relay_encrypted_to_plain(writer, buf).await  {
                                Ok(n) => {
                                    println!("relay encrypt to plain: {}", n);
                                    size += n;
                                }
                                Err(err) => {
                                    println!("relay encrypt to plain error: {}", err);
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

    #[inline]
    async fn relay_encrypted_to_plain(
        &mut self,
        writer: &mut Writer,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        let reader = &mut self.reader;
        self.encryption.read_specific_msg(reader, DATA, buf).await?;
        writer
            .write_all(buf)
            .await
            .with_context(|| "Failed to write to stream")?;
        Ok(buf.len())
    }
}

impl fmt::Display for ReadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReadSession({}-{})",
            self.reader.peer_addr(),
            self.reader.local_addr()
        )
    }
}

pub struct WriteSession {
    writer: Writer,
    encryption: Encryption,
}

impl WriteSession {
    pub fn new(writer: Writer, secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            writer,
            encryption: Encryption::new(secret_iv, aead),
        }
    }

    pub async fn write_connect_msg(&mut self, address: Address) -> Result<()> {
        let buf = &mut BytesMut::with_capacity(32);
        buf.put_slice(address.as_string().as_bytes());
        self.encryption
            .write_message(&mut self.writer, CONNECT, buf)
            .await
    }

    pub async fn relay_plain_to_encrypted_forever(
        &mut self,
        controller: Controller,
        reader: &mut Reader,
    ) -> usize {
        let mut size: usize = 0;
        let buf = &mut BytesMut::with_capacity(4096);
        loop {
            buf.resize(4096, 0);
            tokio::select! {
                _ = async move {
                    loop {
                            match self.replay_plain_to_encrypted(reader, buf).await  {
                                Ok(n) => {
                                    println!("relay plain to encrypt: {}", n);
                                    size += n;
                                }
                                Err(err) => {
                                    println!("relay plain to encrypt error: {}", err);
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

    #[inline]
    async fn replay_plain_to_encrypted(
        &mut self,
        reader: &mut Reader,
        buf: &mut BytesMut,
    ) -> Result<usize> {
        let writer = &mut self.writer;
        let n = reader
            .read(buf)
            .await
            .with_context(|| "Failed to read message from stream")?;
        buf.resize(n, 0);
        self.encryption.write_message(writer, DATA, buf).await?;
        Ok(n)
    }

    async fn write_data(&mut self, payload: &[u8]) -> Result<()> {
        let writer = &mut self.writer;
        self.encryption.write_message(writer, DATA, payload).await
    }
}

impl fmt::Display for WriteSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WriteSession({}-{})",
            self.writer.peer_addr(),
            self.writer.local_addr()
        )
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

    #[allow(dead_code)]
    pub fn signer(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private)
    }

    #[allow(dead_code)]
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
    use crate::transport::{Stream, create_controller};

    use super::*;
    use env_logger;

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

    async fn build_stream_pair() -> (Stream, Stream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        println!("Connected: {}", client.local_addr().unwrap());
        let server = listener.accept().await.unwrap().0;
        println!("Accepted: {}", server.peer_addr().unwrap());
        (
            Stream::from_tcp_stream(client),
            Stream::from_tcp_stream(server),
        )
    }

    #[tokio::test]
    #[timeout(2000)]
    async fn test_plain_message_read_write() {
        let (mut client, mut server) = build_stream_pair().await;
        let mut buf = BytesMut::with_capacity(256);
        buf.put_slice(b"hello world");

        let mut msg = start_msg(DATA, buf.len());
        msg.put_slice(&buf);
        assert_eq!(HEADER_SIZE + buf.len(), msg.len());
        client.writer.write_all(&msg).await.unwrap();

        let (typ, recv) = read_msg(&mut server.reader).await.unwrap();
        assert_eq!(DATA, typ);
        assert_eq!(buf.as_ref(), recv.as_ref());
    }

    #[test]
    fn test_encrypt_and_decrypt() {
    }

    #[tokio::test]
    #[timeout(2000)]
    async fn test_encrypted_message_read_write() {
        let (client, server) = build_stream_pair().await;
        let mut buf = BytesMut::with_capacity(256);
        buf.put_slice(b"hello world");

        env_logger::init();
        let client_key = KeyPair::random();
        let server_key = KeyPair::random();
        let client_singer = &client_key.signer();
        let client_verifier = &server_key.verifier();
        let server_singer = &server_key.signer();
        let server_verifier = &client_key.verifier();

        let ((mut client_read, mut client_write), (mut server_read, mut server_write)) = tokio::join!(
            async move {
                client_handshake(client.reader, client.writer, client_singer, client_verifier)
                    .await
                    .unwrap()
            },
            async move {
                server_handshake(server.reader, server.writer, server_singer, server_verifier)
                    .await
                    .unwrap()
            },
        );
        println!("handshake done");
        client_write.write_data(&buf).await.unwrap();
        println!("client write done");
        let payload = &mut BytesMut::with_capacity(256);
        server_read.read_msg(payload).await.unwrap();
        println!("server read done");
        assert_eq!(buf.as_ref(), payload.as_ref());
        server_write.write_data(&payload).await.unwrap();
        println!("server write done");
        payload.clear();
        client_read.read_msg(payload).await.unwrap();
        println!("client read done");
        assert_eq!(buf.as_ref(), payload.as_ref());
    }

    #[tokio::test]
    #[timeout(9000)]
    async fn test_handshake_and_transfer() {
        env_logger::init();
        let client_key = KeyPair::random();
        let server_key = KeyPair::random();

        // stream structure:
        // peer_client <-tcp-> peer_server <-copy-> server <-tcp-> client <-copy-> local_server <-tcp-> local_client
        let (client, server) = build_stream_pair().await;
        let (mut peer_client, mut peer_server) = build_stream_pair().await;
        let (mut local_client, mut local_server) = build_stream_pair().await;

        let client_singer = &client_key.signer();
        let client_verifier = &server_key.verifier();
        let server_singer = &server_key.signer();
        let server_verifier = &client_key.verifier();
        let (controller, _) = create_controller();
        let controller = &controller;
        tokio::join!(
            async move {
                let (mut read_half, mut write_half) =
                    client_handshake(client.reader, client.writer, client_singer, client_verifier)
                        .await
                        .unwrap();
                println!("Client handshake done");
                tokio::join!(
                    copy_encrypted_bidirectional(
                        controller.clone(),
                        &mut read_half,
                        &mut write_half,
                        &mut local_server.reader,
                        &mut local_server.writer,
                    ),
                    async move {
                        const EXPECTED: &[u8] = b"Hello world";
                        local_client.writer.write_all(EXPECTED).await.unwrap();
                        println!("peer write done");
                        let mut buf = [0u8; EXPECTED.len()];
                        local_client.reader.read(&mut buf).await.unwrap();
                        println!("peer read done");
                        assert_eq!(EXPECTED, &buf);
                    }
                )
            },
            async move {
                let (mut read_half, mut write_half) =
                    server_handshake(server.reader, server.writer, server_singer, server_verifier)
                        .await
                        .unwrap();
                println!("Server handshake done");
                tokio::join!(
                    copy_encrypted_bidirectional(
                        controller.clone(),
                        &mut read_half,
                        &mut write_half,
                        &mut peer_server.reader,
                        &mut peer_server.writer,
                    ),
                    async move {
                        const EXPECTED: &[u8] = b"Hello world";
                        peer_client.writer.write_all(EXPECTED).await.unwrap();
                        println!("local write done");
                        let mut buf = [0u8; EXPECTED.len()];
                        peer_client.reader.read(&mut buf).await.unwrap();
                        println!("local read done");
                        assert_eq!(EXPECTED, &buf);
                    }
                )
            }
        );
    }
}
