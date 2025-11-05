use std::array;
use std::fmt;
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

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum MessageType {
    Handshake,
    Connect,
    Data,
    Ping,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::Handshake => write!(f, "Handshake"),
            MessageType::Connect => write!(f, "Connect"),
            MessageType::Data => write!(f, "Data"),
            MessageType::Ping => write!(f, "Ping"),
        }
    }
}

impl MessageType {
    const HANDSHAKE: u8 = 0b11000000;
    const CONNECT: u8 = 0b10000000;
    const DATA: u8 = 0b01000000;
    const PING: u8 = 0b00000000;

    fn from_checked_u8(msg_type: u8) -> Self {
        Self::from_u8(msg_type).unwrap()
    }

    fn from_u8(msg_type: u8) -> Result<Self> {
        match msg_type {
            Self::HANDSHAKE => Ok(MessageType::Handshake),
            Self::CONNECT => Ok(MessageType::Connect),
            Self::DATA => Ok(MessageType::Data),
            Self::PING => Ok(MessageType::Ping),
            _ => Err(anyhow!("Invalid message type: {}", msg_type)),
        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            MessageType::Handshake => Self::HANDSHAKE,
            MessageType::Connect => Self::CONNECT,
            MessageType::Data => Self::DATA,
            MessageType::Ping => Self::PING,
        }
    }
}

/*
2 byte header fields looks like:

[2bit msg type ] [ 14 bit msg length ]
[            msg data                ]
*/
struct Message(BytesMut);

impl Default for Message {
    fn default() -> Self {
        Message(BytesMut::with_capacity(4096))
    }
}

impl Message {
    const MSG_TYPE_FLAG: u8 = 0b11000000;
    const DATA_SIZE_HIGH_FLAG: u8 = 0b00111111;
    const MAX_MSG_SIZE: usize = 0b00111111_11111111;
    const HEADER_SIZE: usize = 2;

    fn new(buf: BytesMut) -> Self {
        Message(buf)
    }

    fn get_type(&self) -> MessageType {
        MessageType::from_checked_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    fn get_unchecked_type(&self) -> Result<MessageType> {
        MessageType::from_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    fn get_payload_size(&self) -> usize {
        u16::from_be_bytes([self.0[0] & Self::DATA_SIZE_HIGH_FLAG, self.0[1]]) as usize
    }

    fn get_payload(&self) -> &[u8] {
        &self.0[2..]
    }

    fn set_header(&mut self, msg_type: MessageType, body_size: usize) {
        let high = (body_size >> 8) as u8;
        let low = (body_size & 0xff) as u8;
        let buf = &mut self.0;
        assert!(buf.len() > 1);
        buf[0] = high | msg_type.to_u8();
        buf[1] = low;
    }

    fn fill_payload<Output, F: FnOnce(&mut BytesMut) -> Output>(
        &mut self,
        msg_type: MessageType,
        f: F,
    ) -> Output {
        self.0.resize(Self::HEADER_SIZE, 0);
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        let output = f(&mut payload);
        let payload_size = payload.len();
        assert!(payload_size <= Self::MAX_MSG_SIZE);
        self.0.unsplit(payload);
        self.set_header(msg_type, payload_size);
        output
    }

    #[allow(dead_code)]
    async fn read_from(reader: &mut Reader) -> Result<Self> {
        let mut msg = Self::default();
        msg.read_from_inplace(reader).await?;
        Ok(msg)
    }

    async fn read_from_inplace(&mut self, reader: &mut Reader) -> Result<()> {
        self.0.resize(Self::HEADER_SIZE, 0);
        reader
            .read_exact(&mut self.0)
            .await
            .with_context(|| "Failed to read header from stream")?;
        self.get_unchecked_type()?;
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        payload.resize(self.get_payload_size(), 0);
        reader
            .read_exact(&mut payload)
            .await
            .with_context(|| "Failed to read message from stream")?;
        self.0.unsplit(payload);
        Ok(())
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct HelloMessage(Message);

impl AsRef<[u8]> for HelloMessage {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Default for HelloMessage {
    fn default() -> Self {
        HelloMessage(Message::new(BytesMut::with_capacity(
            HelloMessage::SIZE + Message::HEADER_SIZE,
        )))
    }
}

impl HelloMessage {
    const SIZE: usize = 128;

    #[allow(dead_code)]
    fn from_message(msg: Message, verifier: &VerifyingKey) -> Result<Self> {
        let msg = HelloMessage(msg);
        msg.verify(verifier)?;
        Ok(msg)
    }

    fn get_public_key<'a>(&'a self) -> &'a PublicKey {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        buf[0..32].try_into().unwrap()
    }
    fn get_random_key<'a>(&'a self) -> &'a RandomKey {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        buf[32..64].try_into().unwrap()
    }

    fn get_verify_part<'a>(&'a self) -> &'a [u8] {
        &self.0.get_payload()[..64]
    }

    fn get_signature<'a>(&'a self) -> Signature {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        Signature::from_slice(&buf[64..128]).unwrap()
    }

    fn get_payload<'a>(&'a self) -> &'a [u8] {
        self.0.get_payload()
    }

    fn build(
        ephemeral_public: &PublicKey,
        random: &RandomKey,
        signer: &SigningKey,
    ) -> Result<Self> {
        let mut hello = Self::default();
        hello.build_inplace(ephemeral_public, random, signer)?;
        Ok(hello)
    }

    fn build_inplace(
        &mut self,
        ephemeral_public: &PublicKey,
        random: &RandomKey,
        signer: &SigningKey,
    ) -> Result<()> {
        self.0
            .fill_payload(MessageType::Handshake, move |buf| -> Result<()> {
                buf.put_slice(ephemeral_public);
                buf.put_slice(random);
                let signature = signer
                    .try_sign(&buf)
                    .with_context(|| "Failed to sign client hello")?;
                buf.put_slice(signature.r_bytes());
                buf.put_slice(signature.s_bytes());
                assert_eq!(buf.len(), Self::SIZE,);
                Ok(())
            })
    }

    async fn read_from(reader: &mut Reader, verifier: &VerifyingKey) -> Result<Self> {
        let mut hello = Self::default();
        hello.read_from_inplace(reader, verifier).await?;
        Ok(hello)
    }

    async fn read_from_inplace(
        &mut self,
        reader: &mut Reader,
        verifier: &VerifyingKey,
    ) -> Result<()> {
        self.0.read_from_inplace(reader).await?;
        self.verify(verifier)?;
        Ok(())
    }

    fn verify(&self, verifier: &VerifyingKey) -> Result<()> {
        let payload = self.0.get_payload();
        if payload.len() != Self::SIZE {
            return Err(anyhow!(
                "Invalid client hello msg length: {}",
                payload.len()
            ));
        }
        let signature = self.get_signature();
        verifier
            .verify_strict(self.get_verify_part(), &signature)
            .with_context(|| "Failed to verify client hello signature")?;
        Ok(())
    }
}

type ServerHello = HelloMessage;
type ClientHello = HelloMessage;

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
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> anyhow::Result<(ReadSession, WriteSession)> {
    let ephemeral_private = ECDHPrivate::random();
    let ephemeral_public = ECDHPublic::from(&ephemeral_private);
    let client_random = generate_random()?;
    let mut hash = Sha256::new();

    let client_hello = ClientHello::build(ephemeral_public.as_bytes(), &client_random, signer)?;
    writer
        .write_all(client_hello.as_ref())
        .await
        .with_context(|| "Failed to write to stream")?;
    hash.update(client_hello.get_payload());

    let server_hello = ServerHello::read_from(&mut reader, verifier).await?;
    hash.update(server_hello.get_payload());
    let hello_hash = hash.finalize();
    let their_public = ECDHPublic::from(server_hello.get_public_key().clone());
    let shared_key = ephemeral_private.diffie_hellman(&their_public);

    let (client_secret_iv, client_secret, server_secret_iv, server_secret) = expand_secret(
        &client_random,
        server_hello.get_random_key(),
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
    let mut hash = Sha256::new();

    let client_hello = ClientHello::read_from(&mut reader, verifier).await?;
    hash.update(client_hello.get_payload());

    let server_hello = ServerHello::build(ecdh_public.as_bytes(), &server_random, signer)?;
    writer
        .write_all(server_hello.as_ref())
        .await
        .with_context(|| "Failed to write to stream")?;
    hash.update(server_hello.get_payload());

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
    message: Message,
}

impl Encryption {
    pub fn new(secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            secret_iv,
            sequence: Seq([0; 12]),
            aead,
            message: Message::default(),
        }
    }

    async fn read_msg(&mut self, reader: &mut Reader, buf: &mut BytesMut) -> Result<MessageType> {
        self.message.read_from_inplace(reader).await?;
        self.decrypt_inplace(buf)?;
        Ok(self.message.get_type())
    }

    fn decrypt_inplace(&mut self, buf: &mut BytesMut) -> Result<()> {
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        let payload = self.message.get_payload();
        self.aead
            .decrypt_in_place(&nonce.into(), payload, buf)
            .with_context(|| "Failed to decrypt message")?;
        self.sequence.incr();
        Ok(())
    }

    fn encrypt_message_inplace(&mut self, msg_type: MessageType, body: &[u8]) -> Result<()> {
        self.message.fill_payload(msg_type, |payload| {
            let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
            self.aead
                .encrypt_in_place(&nonce.into(), body, payload)
                .with_context(|| "Failed to encrypt message")
        })?;
        assert_eq!(self.message.get_type(), msg_type);
        self.sequence.incr();
        Ok(())
    }

    async fn read_specific_msg(
        &mut self,
        reader: &mut Reader,
        expect_type: MessageType,
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
        msg_type: MessageType,
        body: &[u8],
    ) -> Result<()> {
        self.encrypt_message_inplace(msg_type, body)?;
        writer
            .write_all(self.message.as_ref())
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
            .read_specific_msg(&mut self.reader, MessageType::Connect, buf)
            .await?;
        let addr = Address::from_bytes(buf)?;
        Ok(addr)
    }

    #[inline]
    #[allow(dead_code)]
    pub async fn read_msg(&mut self, buf: &mut BytesMut) -> Result<MessageType> {
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
        self.encryption
            .read_specific_msg(reader, MessageType::Data, buf)
            .await?;
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
            .write_message(&mut self.writer, MessageType::Connect, buf)
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
        self.encryption
            .write_message(writer, MessageType::Data, buf)
            .await?;
        Ok(n)
    }

    #[inline]
    #[allow(dead_code)]
    async fn write_data(&mut self, payload: &[u8]) -> Result<()> {
        let writer = &mut self.writer;
        self.encryption
            .write_message(writer, MessageType::Data, payload)
            .await
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
        let hello = ClientHello::build(&secret.public, &random, &secret.signer()).unwrap();

        let buf = BytesMut::from(hello.as_ref());
        let client_hello =
            ClientHello::from_message(Message::new(buf), &secret.verifier()).unwrap();
        assert_eq!(&secret.public, client_hello.get_public_key());
        assert_eq!(&random, client_hello.get_random_key());
        assert_eq!(hello.get_payload(), client_hello.get_payload());
        assert_eq!(
            hello.get_signature().to_bytes(),
            client_hello.get_signature().to_bytes()
        );
    }

    #[test]
    fn test_server_hello_build_and_parse() {
        let secret = KeyPair::random();
        let random = generate_random().unwrap();
        let hello = ServerHello::build(&secret.public, &random, &secret.signer()).unwrap();

        let buf = BytesMut::from(hello.as_ref());
        let server_hello =
            ServerHello::from_message(Message::new(buf), &secret.verifier()).unwrap();
        assert_eq!(&secret.public, server_hello.get_public_key());
        assert_eq!(&random, server_hello.get_random_key());
        assert_eq!(hello.get_payload(), server_hello.get_payload());
        assert_eq!(
            hello.get_signature().to_bytes(),
            server_hello.get_signature().to_bytes()
        );
    }

    use ntest::timeout;
    use tokio;
    use tokio::net::{TcpListener, TcpStream};

    fn test_setup() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

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
        let expected = b"hello world".as_ref();
        let mut msg = Message::default();
        msg.fill_payload(MessageType::Data, move |buf| {
            buf.put(expected);
        });
        client.writer.write_all(msg.as_ref()).await.unwrap();

        let recv = Message::read_from(&mut server.reader).await.unwrap();
        assert_eq!(MessageType::Data, recv.get_type());
        assert_eq!(expected, recv.get_payload());
    }

    #[test]
    fn test_encrypt_and_decrypt() {}

    #[tokio::test]
    #[timeout(2000)]
    async fn test_encrypted_message_read_write() {
        test_setup();

        let (client, server) = build_stream_pair().await;
        let mut buf = BytesMut::with_capacity(256);
        buf.put_slice(b"hello world");
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
        test_setup();

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
