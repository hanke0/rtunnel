use std::array;
use std::fmt;

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadMutInPlace, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
use bytes::{BufMut, BytesMut};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use log::{debug, info};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret as ECDHPrivate, PublicKey as ECDHPublic};

use crate::errors::{self, Context, Result, is_relay_critical_error};
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
            _ => Err(errors::format_err!("Invalid message type: {}", msg_type)),
        }
    }

    fn as_u8(&self) -> u8 {
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
pub struct Message(BytesMut);

impl Message {
    const MSG_TYPE_FLAG: u8 = 0b11000000;
    const DATA_SIZE_HIGH_FLAG: u8 = 0b00111111;
    const MAX_MSG_SIZE: usize = 0b00111111_11111111;
    const HEADER_SIZE: usize = 2;

    fn with_capacity(capacity: usize) -> Self {
        let mut buf = BytesMut::with_capacity(capacity + Self::HEADER_SIZE);
        buf.resize(Self::HEADER_SIZE, 0);
        let mut message = Message(buf);
        message.set_header(MessageType::Ping, 0);
        message
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
        &self.0[Self::HEADER_SIZE..]
    }

    fn set_header(&mut self, msg_type: MessageType, body_size: usize) {
        let high = (body_size >> 8) as u8;
        let low = (body_size & 0xff) as u8;
        let buf = &mut self.0;
        assert!(buf.len() > 1);
        buf[0] = high | msg_type.as_u8();
        buf[1] = low;
    }

    pub fn rewrite_payload<O, F: FnOnce(&mut BytesMut) -> O>(
        &mut self,
        message_type: MessageType,
        f: F,
    ) -> O {
        assert!(
            self.0.len() >= Self::HEADER_SIZE,
            "Invalid message size: {}",
            self.0.len()
        );
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        assert_eq!(self.0.len(), Self::HEADER_SIZE);
        let output = f(&mut payload);
        let payload_size = payload.len();
        assert!(payload_size <= Self::MAX_MSG_SIZE);
        assert_eq!(self.0.len(), Self::HEADER_SIZE);
        self.0.unsplit(payload);
        assert_eq!(self.0.len(), Self::HEADER_SIZE + payload_size);
        self.set_header(message_type, payload_size);
        output
    }

    pub fn replace_payload<O, F: FnOnce(&mut BytesMut) -> O>(
        &mut self,
        message_type: MessageType,
        f: F,
    ) -> O {
        assert!(
            self.0.len() >= Self::HEADER_SIZE,
            "Invalid message size: {}",
            self.0.len()
        );
        self.rewrite_payload(message_type, move |payload| {
            payload.clear();
            f(payload)
        })
    }

    pub async fn async_replace_payload<O, F>(&mut self, message_type: MessageType, f: F) -> O
    where
        F: AsyncFnOnce(&mut BytesMut) -> O,
    {
        self.0.resize(Self::HEADER_SIZE, 0);
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        let output = f(&mut payload).await;
        let payload_size = payload.len();
        assert!(payload_size <= Self::MAX_MSG_SIZE);
        self.0.unsplit(payload);
        self.set_header(message_type, payload_size);
        output
    }

    #[allow(dead_code)]
    async fn read_from(controller: &Controller, reader: &mut Reader) -> Result<Self> {
        let mut msg = Self::default();
        msg.read_from_inplace(controller, reader).await?;
        Ok(msg)
    }

    async fn read_from_inplace(
        &mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<()> {
        self.0.resize(Self::HEADER_SIZE, 0);
        reader
            .read_exact(controller, &mut self.0)
            .await
            .context("Failed to read message header from stream")?;
        self.get_unchecked_type()?;
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        payload.resize(self.get_payload_size(), 0);
        reader
            .read_exact(controller, &mut payload)
            .await
            .context("Failed to read message from stream")?;
        self.0.unsplit(payload);
        Ok(())
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::with_capacity(4096 - Self::HEADER_SIZE)
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
        HelloMessage(Message::with_capacity(Self::SIZE))
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

    fn get_public_key(&self) -> &PublicKey {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        buf[0..32].try_into().unwrap()
    }
    fn get_random_key(&self) -> &RandomKey {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        buf[32..64].try_into().unwrap()
    }

    fn get_verify_part(&self) -> &[u8] {
        &self.0.get_payload()[..64]
    }

    fn get_signature(&self) -> Signature {
        let buf = self.0.get_payload();
        assert!(buf.len() == Self::SIZE);
        Signature::from_slice(&buf[64..128]).unwrap()
    }

    fn get_payload(&self) -> &[u8] {
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
            .replace_payload(MessageType::Handshake, move |buf| -> Result<()> {
                buf.put_slice(ephemeral_public);
                buf.put_slice(random);
                let signature = signer
                    .try_sign(buf)
                    .map_err(errors::from_error)
                    .context("Failed to sign client hello")?;
                buf.put_slice(signature.r_bytes());
                buf.put_slice(signature.s_bytes());
                assert_eq!(buf.len(), Self::SIZE,);
                Ok(())
            })
    }

    async fn read_from(
        controller: &Controller,
        reader: &mut Reader,
        verifier: &VerifyingKey,
    ) -> Result<Self> {
        let mut hello = Self::default();
        hello
            .read_from_inplace(controller, reader, verifier)
            .await?;
        Ok(hello)
    }

    async fn read_from_inplace(
        &mut self,
        controller: &Controller,
        reader: &mut Reader,
        verifier: &VerifyingKey,
    ) -> Result<()> {
        self.0.read_from_inplace(controller, reader).await?;
        self.verify(verifier)
            .context("Failed to verify hello message")?;
        Ok(())
    }

    fn verify(&self, verifier: &VerifyingKey) -> Result<()> {
        let payload = self.0.get_payload();
        if payload.len() != Self::SIZE {
            return Err(errors::format_err!(
                "Invalid hello msg length: {}",
                payload.len()
            ));
        }
        let signature = self.get_signature();
        verifier
            .verify_strict(self.get_verify_part(), &signature)
            .map_err(errors::from_error)
            .context("Failed to verify hello message signature")?;
        Ok(())
    }
}

type ServerHello = HelloMessage;
type ClientHello = HelloMessage;

fn generate_random() -> Result<RandomKey> {
    generate_random_array::<32>()
}

fn generate_random_array<const N: usize>() -> Result<[u8; N]> {
    let mut random = [0u8; N];
    OsRng
        .try_fill_bytes(random.as_mut())
        .map_err(errors::from_error)
        .context("Failed to generate random bytes")?;
    Ok(random)
}

enum HandshakeSide {
    Client,
    Server,
}

fn handshake(
    client_hello: &ClientHello,
    server_hello: &ServerHello,
    ephemeral_private: ECDHPrivate,
    side: HandshakeSide,
) -> (Encryption, Encryption) {
    let mut hash = Sha256::new();
    hash.update(client_hello.get_payload());
    hash.update(server_hello.get_payload());
    let hello_hash = hash.finalize();
    let their_public = match side {
        HandshakeSide::Client => ECDHPublic::from(*server_hello.get_public_key()),
        HandshakeSide::Server => ECDHPublic::from(*client_hello.get_public_key()),
    };
    let shared_key = ephemeral_private.diffie_hellman(&their_public);
    let (client_secret_iv, client_secret, server_secret_iv, server_secret) = expand_secret(
        client_hello.get_random_key(),
        server_hello.get_random_key(),
        shared_key.as_bytes(),
        &hello_hash,
    );
    (
        Encryption::new(client_secret_iv, Aes256Gcm::new(&client_secret.into())),
        Encryption::new(server_secret_iv, Aes256Gcm::new(&server_secret.into())),
    )
}

pub async fn client_handshake(
    controller: &Controller,
    mut reader: Reader,
    mut writer: Writer,
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> Result<(ReadSession, WriteSession)> {
    let ephemeral_private = ECDHPrivate::random();
    let ephemeral_public = ECDHPublic::from(&ephemeral_private);
    let client_random = generate_random()?;

    let client_hello = ClientHello::build(ephemeral_public.as_bytes(), &client_random, signer)?;
    writer
        .write_all(controller, client_hello.as_ref())
        .await
        .context("Failed to write to stream when client handshake")?;
    let server_hello = ServerHello::read_from(controller, &mut reader, verifier).await?;
    let (client_encryption, server_encryption) = handshake(
        &client_hello,
        &server_hello,
        ephemeral_private,
        HandshakeSide::Client,
    );

    Ok((
        ReadSession::new(reader, server_encryption),
        WriteSession::new(writer, client_encryption),
    ))
}

pub async fn server_handshake(
    controller: &Controller,
    mut reader: Reader,
    mut writer: Writer,
    signer: &SigningKey,
    verifier: &VerifyingKey,
) -> Result<(ReadSession, WriteSession)> {
    let ephemeral_private = ECDHPrivate::random();
    let ephemeral_public = ECDHPublic::from(&ephemeral_private);
    let server_random = generate_random()?;

    let client_hello = ClientHello::read_from(controller, &mut reader, verifier).await?;
    let server_hello = ServerHello::build(ephemeral_public.as_bytes(), &server_random, signer)?;
    writer
        .write_all(controller, server_hello.as_ref())
        .await
        .context("Failed to write to stream when server handshake")?;

    let (client_encryption, server_encryption) = handshake(
        &client_hello,
        &server_hello,
        ephemeral_private,
        HandshakeSide::Server,
    );
    Ok((
        ReadSession::new(reader, client_encryption),
        WriteSession::new(writer, server_encryption),
    ))
}

pub async fn copy_encrypted_bidirectional(
    controller: &Controller,
    read_half: &mut ReadSession,
    write_half: &mut WriteSession,
    raw_reader: &mut Reader,
    raw_writer: &mut Writer,
) -> Result<(usize, usize)> {
    if controller.has_cancel() {
        debug!(
            "{}->{} copy_encrypted_bidirectional cancelled",
            read_half, raw_reader
        );
        return Ok((0, 0));
    }
    let children = &controller.children();
    let (read_size, write_size) = tokio::join!(
        async move {
            let size = read_half
                .relay_encrypted_to_plain_forever(children, raw_writer)
                .await;
            children.cancel();
            size
        },
        async move {
            let size = write_half
                .relay_plain_to_encrypted_forever(children, raw_reader)
                .await;
            children.cancel();
            size
        },
    );
    Ok((read_size?, write_size?))
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

pub struct Encryption {
    secret_iv: NonceB,
    sequence: Seq,
    cipher: Aes256Gcm,
    message: Message,
}

impl Encryption {
    pub fn new(secret_iv: NonceB, aead: Aes256Gcm) -> Self {
        Self {
            secret_iv,
            sequence: Seq([0; 12]),
            cipher: aead,
            message: Message::default(),
        }
    }

    async fn read_message<'a>(
        &'a mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<(MessageType, &'a [u8])> {
        self.message.read_from_inplace(controller, reader).await?;
        self.decrypt_inplace()?;
        Ok((self.message.get_type(), self.message.get_payload()))
    }

    async fn inplace_from_reader<'a>(
        &'a mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<(usize, &'a [u8])> {
        let message = &mut self.message;
        let n = message
            .async_replace_payload(MessageType::Data, async move |payload| -> Result<usize> {
                // https://stackoverflow.com/questions/67028762/why-aes-256-with-gcm-adds-16-bytes-to-the-ciphertext-size
                // nonce(12) + ciphertext + tag(16)
                const ALLOWED_SIZE: usize = Message::MAX_MSG_SIZE - 12 - 16;
                if payload.capacity() > ALLOWED_SIZE {
                    payload.resize(ALLOWED_SIZE, 0);
                } else {
                    payload.resize(payload.capacity(), 0);
                }
                assert_ne!(payload.len(), 0);
                let n = reader
                    .read(controller, payload)
                    .await
                    .context("Failed to read from stream")?;
                payload.resize(n, 0);
                Ok(n)
            })
            .await?;
        if n == 0 {
            return Ok((0, &[]));
        }
        self.encrypt_inplace(MessageType::Data)?;
        Ok((n, self.message.as_ref()))
    }

    fn replace_payload<'a>(
        &'a mut self,
        message_type: MessageType,
        payload: &[u8],
    ) -> Result<&'a [u8]> {
        self.message
            .replace_payload(message_type, |buf| buf.extend_from_slice(payload));
        self.encrypt_inplace(message_type)?;
        Ok(self.message.as_ref())
    }

    fn decrypt_inplace(&mut self) -> Result<()> {
        let message = &mut self.message;
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        let cipher = &mut self.cipher;
        let associated_data = self.sequence.as_ref();
        let typ = message.get_type();
        message.rewrite_payload(message.get_type(), move |buf| {
            cipher
                .decrypt_in_place(&nonce.into(), associated_data, buf)
                .map_err(errors::from_error)
                .context("Failed to decrypt message")
        })?;
        assert_eq!(self.message.get_type(), typ);
        self.sequence.incr();
        Ok(())
    }

    fn encrypt_inplace(&mut self, msg_type: MessageType) -> Result<()> {
        let message = &mut self.message;
        let nonce = self.sequence.xor_secret_iv(&self.secret_iv);
        let cipher = &mut self.cipher;
        let associated_data = self.sequence.as_ref();

        message.rewrite_payload(msg_type, |payload| {
            cipher
                .encrypt_in_place(&nonce.into(), associated_data, payload)
                .map_err(errors::from_error)
                .context("Failed to encrypt message")
        })?;
        assert_eq!(self.message.get_type(), msg_type);
        self.sequence.incr();
        Ok(())
    }
}

pub struct ReadSession {
    reader: Reader,
    encryption: Encryption,
}

impl fmt::Display for ReadSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reader)
    }
}

impl ReadSession {
    pub fn new(reader: Reader, encryption: Encryption) -> Self {
        Self { reader, encryption }
    }

    pub async fn read_ping(&mut self, controller: &Controller) -> Result<()> {
        let (typ, _) = self
            .encryption
            .read_message(controller, &mut self.reader)
            .await?;
        match typ {
            MessageType::Ping => Ok(()),
            _ => Err(errors::format_err!("Unexpected message type: {}", typ)),
        }
    }

    pub async fn wait_connect_message(
        &mut self,
        controller: &Controller,
        writer: &mut WriteSession,
    ) -> Result<Address> {
        loop {
            let (typ, payload) = self
                .encryption
                .read_message(controller, &mut self.reader)
                .await?;
            match typ {
                MessageType::Connect => return Address::from_bytes(payload),
                MessageType::Ping => {
                    match writer
                        .write_ping(controller)
                        .await
                        .context("Failed to write ping")
                    {
                        Ok(()) => continue,
                        Err(err) => return Err(err),
                    }
                }
                _ => return Err(errors::format_err!("Unexpected message type: {}", typ)),
            };
        }
    }

    #[inline]
    pub async fn read_message<'a>(
        &'a mut self,
        controller: &Controller,
    ) -> Result<(MessageType, &'a [u8])> {
        self.encryption
            .read_message(controller, &mut self.reader)
            .await
    }

    pub async fn relay_encrypted_to_plain_forever(
        &mut self,
        controller: &Controller,
        writer: &mut Writer,
    ) -> Result<usize> {
        let mut size: usize = 0;
        loop {
            let n = self.relay_encrypted_to_plain(controller, writer).await;
            match n {
                Ok(n) => {
                    if n == 0 {
                        return Ok(size);
                    }
                    size += n;
                }
                Err(err) => {
                    if is_relay_critical_error(&err) {
                        return Err(err);
                    }
                    info!("{self} relay encrypted to plain error: {:#}", err);
                    return Ok(size);
                }
            }
        }
    }

    async fn relay_encrypted_to_plain(
        &mut self,
        controller: &Controller,
        writer: &mut Writer,
    ) -> Result<usize> {
        tokio::select! {
            n = self.relay_encrypted_to_plain_impl(controller, writer) => n,
            _ = controller.wait_cancel() => Ok(0),
        }
    }

    #[inline]
    async fn relay_encrypted_to_plain_impl(
        &mut self,
        controller: &Controller,
        writer: &mut Writer,
    ) -> Result<usize> {
        let (typ, buf) = self.read_message(controller).await?;
        if typ != MessageType::Data {
            return Err(errors::format_err!("Unexpected message type: {}", typ));
        }
        writer
            .write_all(controller, buf)
            .await
            .context("Failed to write to stream")?;
        Ok(buf.len())
    }
}

pub struct WriteSession {
    writer: Writer,
    encryption: Encryption,
}

impl fmt::Display for WriteSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.writer)
    }
}

impl WriteSession {
    pub fn new(writer: Writer, encryption: Encryption) -> Self {
        Self { writer, encryption }
    }

    pub async fn write_ping(&mut self, controller: &Controller) -> Result<()> {
        let data = self.encryption.replace_payload(MessageType::Ping, &[])?;
        self.writer
            .write_all(controller, data)
            .await
            .context("Failed to write ping message to stream")
    }

    pub async fn write_connect_message(
        &mut self,
        controller: &Controller,
        address: &Address,
    ) -> Result<()> {
        let data = self
            .encryption
            .replace_payload(MessageType::Connect, address.as_string().as_bytes())?;
        self.writer
            .write_all(controller, data)
            .await
            .context("Failed to write connect message to stream")
    }

    pub async fn relay_plain_to_encrypted_forever(
        &mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<usize> {
        let mut size: usize = 0;
        loop {
            match self.relay_plain_to_encrypted(controller, reader).await {
                Ok(n) => {
                    if n == 0 {
                        return Ok(size);
                    }
                    size += n;
                }
                Err(err) => {
                    if is_relay_critical_error(&err) {
                        return Err(err);
                    }
                    debug!("{self} relay plain to encrypted error: {:#}", err);
                    return Ok(size);
                }
            }
        }
    }

    async fn relay_plain_to_encrypted(
        &mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<usize> {
        tokio::select! {
            n = self.replay_plain_to_encrypted_impl(controller, reader) => n,
            _ = controller.wait_cancel() => Ok(0),
        }
    }

    #[inline]
    async fn replay_plain_to_encrypted_impl(
        &mut self,
        controller: &Controller,
        reader: &mut Reader,
    ) -> Result<usize> {
        let (n, data) = self
            .encryption
            .inplace_from_reader(controller, reader)
            .await?;
        if n == 0 {
            return Ok(0);
        }
        self.writer
            .write_all(controller, data)
            .await
            .context("Failed to write to stream")?;
        Ok(n)
    }

    #[inline]
    #[allow(dead_code)]
    async fn write_data(&mut self, controller: &Controller, payload: &[u8]) -> Result<()> {
        let data = self
            .encryption
            .replace_payload(MessageType::Data, payload)?;
        self.writer
            .write_all(controller, data)
            .await
            .context("Failed to write to stream")?;
        Ok(())
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

fn vec_to_array<const N: usize>(v: Vec<u8>) -> Result<[u8; N]> {
    let r = v.try_into();
    match r {
        Ok(a) => Ok(a),
        Err(e) => Err(errors::format_err!(
            "key length is mismatch: expect {} got {}",
            N,
            e.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use ntest::timeout;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc::channel;

    use super::*;
    use crate::transport::Stream;

    #[test]
    fn test_split_off() {
        let mut a = BytesMut::from(b"hello world".as_ref());
        let mut b = a.split_off(5);
        assert_eq!(&a[..], b"hello");
        assert_eq!(&b[..], b" world");
        b.clear();
        b.put(b"123".as_ref());
        a.unsplit(b);
        assert_eq!(&a[..], b"hello123");
    }

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
        let n = copy_message(&hello.0);
        let client_hello = ClientHello::from_message(n, &secret.verifier()).unwrap();
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

        let n = copy_message(&hello.0);
        let server_hello = ServerHello::from_message(n, &secret.verifier()).unwrap();
        assert_eq!(&secret.public, server_hello.get_public_key());
        assert_eq!(&random, server_hello.get_random_key());
        assert_eq!(hello.get_payload(), server_hello.get_payload());
        assert_eq!(
            hello.get_signature().to_bytes(),
            server_hello.get_signature().to_bytes()
        );
    }

    fn test_setup() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    async fn build_stream_pair() -> (Stream, Stream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let server = listener.accept().await.unwrap().0;
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
        msg.replace_payload(MessageType::Data, move |buf| {
            buf.put(expected);
        });
        let controller = Controller::default();
        client
            .writer
            .write_all(&controller, msg.as_ref())
            .await
            .unwrap();

        let recv = Message::read_from(&controller, &mut server.reader)
            .await
            .unwrap();
        assert_eq!(MessageType::Data, recv.get_type());
        assert_eq!(expected, recv.get_payload());
    }

    fn copy_message(m: &Message) -> Message {
        let mut n = Message::with_capacity(m.as_ref().len());
        n.replace_payload(m.get_type(), |buf| {
            buf.put(m.get_payload());
        });
        n
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let client_random = generate_random().unwrap();
        let server_random = generate_random().unwrap();
        let client_private = ECDHPrivate::random();
        let client_public = ECDHPublic::from(&client_private);
        let server_private = ECDHPrivate::random();
        let server_public = ECDHPublic::from(&server_private);
        let signer = SigningKey::from_bytes(&generate_random().unwrap());

        let client_hello =
            ClientHello::build(client_public.as_bytes(), &client_random, &signer).unwrap();
        let server_hello =
            ServerHello::build(server_public.as_bytes(), &server_random, &signer).unwrap();

        let (mut client_write, mut server_read) = handshake(
            &client_hello,
            &server_hello,
            client_private,
            HandshakeSide::Client,
        );
        let (mut client_read, mut server_write) = handshake(
            &client_hello,
            &server_hello,
            server_private,
            HandshakeSide::Server,
        );
        let body = b"hello world".as_ref();

        let mut client_once = || {
            client_write
                .replace_payload(MessageType::Data, body)
                .unwrap();
            client_read.message = copy_message(&client_write.message);
            assert_eq!(client_write.message.as_ref(), client_read.message.as_ref());
            client_read.decrypt_inplace().unwrap();
            assert_eq!(MessageType::Data, client_read.message.get_type());
            assert_eq!(body, client_read.message.get_payload());
        };
        for i in 1..11 {
            println!("Client round: {}", i);
            client_once();
        }

        let mut server_once = || {
            server_write
                .replace_payload(MessageType::Data, body)
                .unwrap();
            server_read.message = copy_message(&server_write.message);
            assert_eq!(server_write.message.as_ref(), server_read.message.as_ref());
            server_read.decrypt_inplace().unwrap();
            assert_eq!(MessageType::Data, server_read.message.get_type());
            assert_eq!(body, server_read.message.get_payload());
        };
        for i in 1..11 {
            println!("Server round: {}", i);
            server_once();
        }
    }

    #[tokio::test]
    #[timeout(1000)]
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
        let controller = &Controller::default();

        let ((mut client_read, mut client_write), (mut server_read, mut server_write)) = tokio::join!(
            async move {
                client_handshake(
                    controller,
                    client.reader,
                    client.writer,
                    client_singer,
                    client_verifier,
                )
                .await
                .unwrap()
            },
            async move {
                server_handshake(
                    controller,
                    server.reader,
                    server.writer,
                    server_singer,
                    server_verifier,
                )
                .await
                .unwrap()
            },
        );
        println!("handshake done");
        client_write.write_data(controller, &buf).await.unwrap();
        println!("client write done");
        let (message_type, payload) = server_read.read_message(controller).await.unwrap();
        println!("server read done");
        assert_eq!(MessageType::Data, message_type);
        assert_eq!(buf.as_ref(), payload);

        server_write.write_data(controller, payload).await.unwrap();
        println!("server write done");
        let (message_type, payload) = client_read.read_message(controller).await.unwrap();
        println!("client read done");
        assert_eq!(MessageType::Data, message_type);
        assert_eq!(buf.as_ref(), payload);
    }

    #[tokio::test]
    #[timeout(1000)]
    async fn test_connect_message() {
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
        let controller = &Controller::default();

        let ((mut client_read, mut client_write), (mut server_read, mut server_write)) = tokio::join!(
            async move {
                client_handshake(
                    controller,
                    client.reader,
                    client.writer,
                    client_singer,
                    client_verifier,
                )
                .await
                .unwrap()
            },
            async move {
                server_handshake(
                    controller,
                    server.reader,
                    server.writer,
                    server_singer,
                    server_verifier,
                )
                .await
                .unwrap()
            },
        );

        let address = Address::from_string("tcp://127.0.0.1:8080").unwrap();
        server_write
            .write_connect_message(controller, &address)
            .await
            .unwrap();
        let recv = client_read
            .wait_connect_message(controller, &mut client_write)
            .await
            .unwrap();
        assert_eq!(address, recv);

        client_write
            .write_connect_message(controller, &address)
            .await
            .unwrap();
        let recv = server_read
            .wait_connect_message(controller, &mut server_write)
            .await
            .unwrap();
        assert_eq!(address, recv);
    }

    #[tokio::test]
    #[timeout(1000)]
    async fn test_message_relay() {
        test_setup();

        let (client, server) = build_stream_pair().await;
        let (mut plain_client, mut plain_server) = build_stream_pair().await;
        let mut buf = BytesMut::with_capacity(256);
        buf.put_slice(b"hello world");
        let client_key = KeyPair::random();
        let server_key = KeyPair::random();
        let client_singer = &client_key.signer();
        let client_verifier = &server_key.verifier();
        let server_singer = &server_key.signer();
        let server_verifier = &client_key.verifier();
        let controller = &Controller::default();

        let ((mut client_read, mut client_write), (mut server_read, mut server_write)) = tokio::join!(
            async move {
                client_handshake(
                    controller,
                    client.reader,
                    client.writer,
                    client_singer,
                    client_verifier,
                )
                .await
                .unwrap()
            },
            async move {
                server_handshake(
                    controller,
                    server.reader,
                    server.writer,
                    server_singer,
                    server_verifier,
                )
                .await
                .unwrap()
            },
        );

        // client write -> server read
        plain_client
            .writer
            .write_all(controller, &buf[..])
            .await
            .unwrap();
        println!("plain write done: {}", buf.len());
        let n = client_write
            .relay_plain_to_encrypted(controller, &mut plain_server.reader)
            .await
            .unwrap();
        println!("relay plain_to_encrypted size: {}", n);
        assert!(n > 0);
        let n = server_read
            .relay_encrypted_to_plain(controller, &mut plain_server.writer)
            .await
            .unwrap();
        println!("relay encrypted_to_plain size: {}", n);
        assert!(n > 0);
        let mut recv = BytesMut::with_capacity(buf.len());
        recv.resize(buf.len(), 0);
        plain_client
            .reader
            .read(controller, &mut recv)
            .await
            .unwrap();
        assert_eq!(buf.as_ref(), recv.as_ref());

        // server write -> client read
        plain_server
            .writer
            .write_all(controller, &buf[..])
            .await
            .unwrap();
        println!("plain write done: {}", buf.len());
        let n = server_write
            .relay_plain_to_encrypted(controller, &mut plain_client.reader)
            .await
            .unwrap();
        println!("relay plain_to_encrypted size: {}", n);
        assert!(n > 0);
        let n = client_read
            .relay_encrypted_to_plain(controller, &mut plain_client.writer)
            .await
            .unwrap();
        println!("relay encrypted_to_plain size: {}", n);
        assert!(n > 0);
        let mut recv = BytesMut::with_capacity(buf.len());
        recv.resize(buf.len(), 0);
        plain_server
            .reader
            .read(controller, &mut recv)
            .await
            .unwrap();
        assert_eq!(buf.as_ref(), recv.as_ref());
    }

    #[tokio::test]
    async fn test_handshake_and_data_transfer() {
        test_setup();

        let client_key = KeyPair::random();
        let server_key = KeyPair::random();
        // stream structure:
        // peer_client <-tcp-> peer_server <-copy-> server <-tcp-> client <-copy-> local_server <-tcp-> local_client
        let (client, server) = build_stream_pair().await;
        let (mut peer_client, mut peer_server) = build_stream_pair().await;
        let (mut local_client, mut local_server) = build_stream_pair().await;
        println!("client: {}", client);
        println!("peer_client: {}", peer_client);
        println!("local_client: {}", local_client);
        println!("server: {}", server);
        println!("peer_server: {}", peer_server);
        println!("local_server: {}", local_server);

        let client_singer = &client_key.signer();
        let client_verifier = &server_key.verifier();
        let server_singer = &server_key.signer();
        let server_verifier = &client_key.verifier();
        let controller = &Controller::default();
        let (sender, mut receiver) = channel(2);
        let sender = &sender;
        let address = Address::from_string("tcp://127.0.0.1:8080").unwrap();

        tokio::join!(
            async move {
                let (mut read_half, mut write_half) = client_handshake(
                    controller,
                    client.reader,
                    client.writer,
                    client_singer,
                    client_verifier,
                )
                .await
                .unwrap();
                println!("Client handshake done");
                read_half
                    .wait_connect_message(controller, &mut write_half)
                    .await
                    .unwrap();
                println!("Client read connect message done");
                tokio::join!(
                    async move {
                        copy_encrypted_bidirectional(
                            controller,
                            &mut read_half,
                            &mut write_half,
                            &mut local_server.reader,
                            &mut local_server.writer,
                        )
                        .await
                        .unwrap();
                    },
                    async move {
                        let mut do_once = async move || {
                            const EXPECTED: &[u8] = b"Hello world";
                            local_client
                                .writer
                                .write_all(controller, EXPECTED)
                                .await
                                .unwrap();
                            let mut buf = [0u8; EXPECTED.len()];
                            peer_client
                                .reader
                                .read_exact(controller, &mut buf)
                                .await
                                .unwrap();
                            assert_eq!(EXPECTED, &buf);
                        };
                        for _ in 0..100 {
                            do_once().await;
                        }
                        sender.send(()).await.unwrap();
                    }
                );
            },
            async move {
                let (mut read_half, mut write_half) = server_handshake(
                    controller,
                    server.reader,
                    server.writer,
                    server_singer,
                    server_verifier,
                )
                .await
                .unwrap();
                println!("Server handshake done");
                write_half
                    .write_connect_message(controller, &address)
                    .await
                    .unwrap();
                println!("Server write connect message done");
                tokio::join!(
                    async move {
                        copy_encrypted_bidirectional(
                            controller,
                            &mut read_half,
                            &mut write_half,
                            &mut peer_server.reader,
                            &mut peer_server.writer,
                        )
                        .await
                        .unwrap();
                    },
                    async move {
                        let mut do_once = async move || {
                            const EXPECTED: &[u8] = b"Hello world";
                            peer_client
                                .writer
                                .write_all(controller, EXPECTED)
                                .await
                                .unwrap();
                            let mut buf = [0u8; EXPECTED.len()];
                            local_client
                                .reader
                                .read_exact(controller, &mut buf)
                                .await
                                .unwrap();
                            assert_eq!(EXPECTED, &buf);
                        };
                        for _ in 0..100 {
                            do_once().await;
                        }
                        sender.send(()).await.unwrap();
                    }
                );
            },
            async move {
                for _ in 0..2 {
                    receiver.recv().await.unwrap();
                }
                println!("task done");
                controller.cancel();
            },
        );
        controller.wait().await;
    }
}
