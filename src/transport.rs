use core::task::{self, Poll};
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::pin::pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use socket2::TcpKeepalive;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::io::{ReadBuf, WriteBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::TlsStream;
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config;
use crate::errors::{Error, Result, ResultExt as _, whatever};

pub fn build_connector(config: config::ConnectTo) -> Result<Connector> {
    match config {
        config::ConnectTo::Tcp { addr } => Ok(Connector::Tcp(TcpConnectTo::new(addr))),
        config::ConnectTo::Tls {
            addr,
            client_cert,
            client_key,
            server_ca,
            subject,
        } => {
            let connector =
                TlsConnectTo::try_from_pem(client_cert, client_key, server_ca, subject, addr)?;
            Ok(Connector::Tls(connector))
        }
    }
}

pub async fn build_listener(config: config::ListenTo) -> Result<Listener> {
    match config {
        config::ListenTo::Tcp { addr } => Ok(Listener::Tcp(TcpListener::bind(addr).await?)),
        config::ListenTo::Tls {
            addr,
            server_cert,
            server_key,
            client_ca,
            subject,
        } => Ok(Listener::Tls(
            TlsListener::listen(server_cert, server_key, client_ca, subject, addr).await?,
        )),
    }
}

/// A bidirectional network stream.
pub enum Stream {
    Tcp(TcpStream, String),
    Tls(TlsStream<TcpStream>, String),
}

impl fmt::Display for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stream::Tcp(_, s) => f.write_str(s),
            Stream::Tls(_, s) => f.write_str(s),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s, _) => pin!(s).poll_read(cx, buf),
            Stream::Tls(s, _) => pin!(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s, _) => pin!(s).poll_write(cx, buf),
            Stream::Tls(s, _) => pin!(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s, _) => pin!(s).poll_flush(cx),
            Stream::Tls(s, _) => pin!(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s, _) => pin!(s).poll_shutdown(cx),
            Stream::Tls(s, _) => pin!(s).poll_shutdown(cx),
        }
    }
}

impl Stream {
    pub fn from_tls_stream(stream: TlsStream<TcpStream>) -> Self {
        let local_addr = stream.get_ref().0.local_addr().unwrap();
        let peer_addr = stream.get_ref().0.peer_addr().unwrap();
        let display = format!("{}-{}", local_addr, peer_addr);
        Stream::Tls(stream, display)
    }

    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let display = format!("{}-{}", local_addr, peer_addr);
        Stream::Tcp(stream, display)
    }
}

/// Network listener for accepting incoming connections.
///
/// This enum represents different types of network listeners that can accept
/// incoming connections and create streams.
pub enum Listener {
    Tcp(TcpListener),
    Tls(TlsListener),
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listener::Tcp(s) => {
                let addr = s.local_addr().unwrap();
                write!(f, "{}", addr)
            }
            Listener::Tls(s) => {
                write!(f, "{}", s.addr)
            }
        }
    }
}

impl Listener {
    pub async fn bind(addr: &str) -> Result<Self> {
        let (typ, addr) = parse_address(addr)?;
        match typ {
            AddrKind::TCP => Ok(Self::Tcp(TcpListener::bind(addr).await?)),
        }
    }

    pub async fn accept(&mut self, context: &Context) -> Result<Stream> {
        tokio::select! {
            _ = context.wait_cancel() => Err(Error::cancel()),
            r = self.accept_impl() => r,
        }
    }

    async fn accept_impl(&mut self) -> Result<Stream> {
        match self {
            Listener::Tcp(s) => {
                let (stream, _) = s.accept().await?;
                set_keep_alive(&stream)?;
                Ok(Stream::from_tcp_stream(stream))
            }
            Listener::Tls(s) => {
                let stream = s.accept().await?;
                Ok(Stream::from_tls_stream(stream))
            }
        }
    }
}

pub struct TlsListener {
    acceptor: TlsAcceptor,
    listener: TcpListener,
    addr: SocketAddr,
    subject: String,
}

impl TlsListener {
    pub async fn listen(
        server_cert: String,
        server_key: String,
        client_ca: String,
        subject: String,
        addr: SocketAddr,
    ) -> Result<Self> {
        let cert_chain = CertificateDer::from_pem_slice(server_cert.as_bytes())?;
        let key_der = PrivateKeyDer::from_pem_slice(server_key.as_bytes())?;
        let client_ca = CertificateDer::from_pem_slice(client_ca.as_bytes())?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(client_ca)?;
        let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(vec![cert_chain], key_der)?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            acceptor,
            listener,
            addr,
            subject,
        })
    }

    async fn accept(&self) -> Result<TlsStream<TcpStream>> {
        let (stream, _) = self.listener.accept().await?;
        set_keep_alive(&stream)?;
        let r = self.acceptor.accept(stream).await?;
        Ok(TlsStream::from(r))
    }
}

pub enum Connector {
    Tls(TlsConnectTo),
    Tcp(TcpConnectTo),
}

enum AddrKind {
    TCP,
}

fn parse_address(value: &str) -> Result<(AddrKind, SocketAddr)> {
    let (typ, addr) = if value.starts_with("tcp://") {
        (AddrKind::TCP, value.strip_prefix("tcp://").unwrap())
    } else {
        (AddrKind::TCP, value)
    };
    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or(whatever!("Invalid address"))?;
    Ok((typ, addr))
}

impl TryFrom<String> for Connector {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        let (typ, addr) = parse_address(&value)?;
        match typ {
            AddrKind::TCP => Ok(Self::Tcp(TcpConnectTo::new(addr))),
        }
    }
}

impl Connector {
    pub async fn connect(&self, context: &Context) -> Result<Stream> {
        tokio::select! {
            _ = context.wait_cancel() => Err(Error::cancel()),
            r = self.connect_impl() => Ok(r?),
        }
    }

    async fn connect_impl(&self) -> Result<Stream> {
        match self {
            Connector::Tls(s) => s.connect().await,
            Connector::Tcp(s) => s.connect().await,
        }
    }
}

pub struct TlsConnectTo {
    connector: TlsConnector,
    addr: SocketAddr,
    server_name: ServerName<'static>,
}

impl TlsConnectTo {
    pub fn try_from_pem(
        client_cert: String,
        client_key: String,
        server_ca: String,
        subject: String,
        addr: SocketAddr,
    ) -> Result<Self> {
        let cert_chain = CertificateDer::from_pem_slice(client_cert.as_bytes())?;
        let key_der = PrivateKeyDer::from_pem_slice(client_key.as_bytes())?;
        let server_ca = CertificateDer::from_pem_slice(server_ca.as_bytes())?;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(server_ca)?;
        let server_name = ServerName::try_from(subject)?;

        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_client_auth_cert(vec![cert_chain], key_der)?;
        let connector = TlsConnector::from(Arc::new(config));
        Ok(Self {
            connector,
            addr,
            server_name,
        })
    }

    pub async fn connect(&self) -> Result<Stream> {
        let stream = TcpStream::connect(self.addr).await?;
        set_keep_alive(&stream)?;
        let stream = self
            .connector
            .connect(self.server_name.clone(), stream)
            .await?;
        Ok(Stream::from_tls_stream(stream.into()))
    }
}

struct TcpConnectTo {
    addr: SocketAddr,
}

impl TcpConnectTo {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub async fn connect(&self) -> Result<Stream> {
        let stream = TcpStream::connect(self.addr).await?;
        set_keep_alive(&stream)?;
        Ok(Stream::from_tcp_stream(stream))
    }
}

fn set_keep_alive(stream: &TcpStream) -> Result<()> {
    let socket_ref = socket2::SockRef::from(stream);
    let keep_alive = TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(1));
    socket_ref.set_tcp_keepalive(&keep_alive)?;
    Ok(())
}

/// Context for managing async tasks and cancellation.
///
/// This struct provides facilities for spawning tasks, managing their lifecycle,
/// and coordinating cancellation across a hierarchy of tasks. It supports creating
/// child context that can be cancelled independently or as part of a parent.
pub struct Context {
    cancel_token: CancellationToken,
    tracker: TaskTracker,
    father: Option<Box<Self>>,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            cancel_token: self.cancel_token.clone(),
            tracker: self.tracker.clone(),
            father: self.father.clone(),
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self {
            cancel_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
            father: None,
        }
    }
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn spawn<F>(&self, task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn(task)
    }

    #[inline]
    pub fn cancel(&self) {
        self.cancel_token.cancel();
        self.tracker.close();
    }

    pub fn cancel_all(&self) {
        self.cancel();
        let father = self.father.clone();
        if let Some(father) = father {
            father.cancel_all();
        }
    }

    #[inline]
    pub fn has_cancel(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    #[inline]
    pub async fn wait(&self) {
        self.wait_cancel().await;
        self.tracker.wait().await;
    }

    #[inline]
    pub async fn wait_cancel(&self) {
        self.cancel_token.cancelled().await;
        self.cancel();
    }

    #[inline]
    pub fn task_count(&self) -> usize {
        self.tracker.len()
    }

    pub fn children(&self) -> Self {
        let me = self.clone();
        let children = Self {
            cancel_token: self.cancel_token.child_token(),
            tracker: TaskTracker::new(),
            father: Some(Box::new(me)),
        };
        let child = children.clone();
        self.spawn(async move {
            child.wait_cancel().await;
            child.wait().await;
        });
        children
    }

    pub async fn timeout<T, E, F>(&self, duration: Duration, f: F) -> Result<T>
    where
        F: IntoFuture<Output = StdResult<T, E>>,
    {
        timeout(duration, f).await
    }

    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
    pub async fn timeout_default<T, E, F>(&self, f: F) -> Result<T>
    where
        F: IntoFuture<Output = StdResult<T, E>>,
    {
        timeout(Self::DEFAULT_TIMEOUT, f).await
    }
}

/// Executes a future with a timeout.
pub async fn timeout<T, E, F>(duration: Duration, f: F) -> Result<T>
where
    F: IntoFuture<Output = StdResult<T, E>>,
{
    match tokio::time::timeout(duration, f).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(Error::from_timeout(duration)),
    }
}

/// Message type enumeration for tunnel protocol messages.
///
/// This enum represents the different types of messages that can be sent
/// over the encrypted tunnel connection.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum MessageType {
    HandshakeData,
    HandshakeCtrl,
    Connect,
    Ping,
}

impl MessageType {
    const HANDSHAKE_DATA: u8 = 0b01000000;
    const HANDSHAKE_CTRL: u8 = 0b10000000;
    const CONNECT: u8 = 0b11000000;
    const PING: u8 = 0b00000000;

    fn from_checked_u8(msg_type: u8) -> Self {
        Self::from_u8(msg_type).unwrap()
    }

    fn from_u8(msg_type: u8) -> Result<Self> {
        match msg_type {
            Self::HANDSHAKE_DATA => Ok(MessageType::HandshakeData),
            Self::CONNECT => Ok(MessageType::Connect),
            Self::HANDSHAKE_CTRL => Ok(MessageType::HandshakeCtrl),
            Self::PING => Ok(MessageType::Ping),
            _ => Err(whatever!("Invalid message type: {}", msg_type)),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            MessageType::HandshakeData => Self::HANDSHAKE_DATA,
            MessageType::Connect => Self::HANDSHAKE_CTRL,
            MessageType::HandshakeCtrl => Self::HANDSHAKE_CTRL,
            MessageType::Ping => Self::PING,
        }
    }
}

/// Protocol message.
///
/// Messages have a 2-byte header containing:
/// - 2 bits for message type
/// - 14 bits for message length
///
/// Followed by the message payload data.
pub struct Message(BytesMut);

impl Message {
    const MSG_TYPE_FLAG: u8 = 0b11000000;
    const DATA_SIZE_HIGH_FLAG: u8 = 0b00111111;
    const MAX_MSG_SIZE: usize = 0b00111111_11111111;
    const HEADER_SIZE: usize = 2;

    pub fn ping() -> Self {
        let mut message = Self::with_capacity(0);
        message.set_header(MessageType::Ping, 0);
        message
    }

    pub fn connect(addr: &str) -> Self {
        let mut message = Self::with_capacity(addr.len());
        message.fill(MessageType::Connect, |buf| {
            buf.extend_from_slice(addr.as_bytes());
        });
        message
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut buf = BytesMut::with_capacity(capacity + Self::HEADER_SIZE);
        buf.resize(Self::HEADER_SIZE, 0);
        let mut message = Message(buf);
        message.set_header(MessageType::Ping, 0);
        message
    }

    pub fn get_type(&self) -> MessageType {
        MessageType::from_checked_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    fn get_unchecked_type(&self) -> Result<MessageType> {
        MessageType::from_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    pub fn get_payload_size(&self) -> usize {
        u16::from_be_bytes([self.0[0] & Self::DATA_SIZE_HIGH_FLAG, self.0[1]]) as usize
    }

    pub fn get_payload(&self) -> &[u8] {
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

    pub fn fill<O, F: FnOnce(&mut BytesMut) -> O>(&mut self, message_type: MessageType, f: F) -> O {
        debug_assert!(
            self.0.len() >= Self::HEADER_SIZE,
            "Invalid message size: {}",
            self.0.len()
        );
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        payload.clear();
        debug_assert_eq!(self.0.len(), Self::HEADER_SIZE);
        let output = f(&mut payload);
        let payload_size = payload.len();
        debug_assert!(payload_size <= Self::MAX_MSG_SIZE);
        debug_assert_eq!(self.0.len(), Self::HEADER_SIZE);
        self.0.unsplit(payload);
        debug_assert_eq!(self.0.len(), Self::HEADER_SIZE + payload_size);
        self.set_header(message_type, payload_size);
        output
    }

    pub async fn read_from(context: &Context, reader: &mut Stream) -> Result<Self> {
        let mut msg = Self::default();
        msg.read_from_inplace(context, reader).await?;
        Ok(msg)
    }

    pub async fn read_from_inplace(
        &mut self,
        context: &Context,
        reader: &mut Stream,
    ) -> Result<()> {
        self.0.resize(Self::HEADER_SIZE, 0);
        reader
            .read_exact(&mut self.0)
            .await
            .context("Failed to read message header from stream")?;
        self.get_unchecked_type()?;
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        payload.resize(self.get_payload_size(), 0);
        reader
            .read_exact(&mut payload)
            .await
            .context("Failed to read message from stream")?;
        self.0.unsplit(payload);
        Ok(())
    }

    pub async fn wait_connect_message(
        &mut self,
        context: &Context,
        reader: &mut Stream,
    ) -> Result<Connector> {
        loop {
            self.read_from_inplace(context, reader).await?;
            match self.get_type() {
                MessageType::Ping => continue,
                MessageType::Connect => break,
                _ => return Err(whatever!("Invalid message type: {:?}", self.get_type())),
            }
        }
        let addr = String::from_utf8(self.get_payload().to_vec()).context("Invalid address")?;
        Ok(addr.try_into()?)
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

#[cfg(test)]
mod tests {

    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    use super::*;

    #[tokio::test]
    async fn test_context_children_wait() {
        let father = Context::default();
        let children = father.children();
        let grandson = children.children();
        let father1 = father.clone();
        let children1 = children.clone();
        let grandson1 = grandson.clone();

        let (sender, receiver) = oneshot::channel();
        assert_eq!(father.task_count(), 1);
        assert_eq!(children.task_count(), 1);
        assert_eq!(grandson.task_count(), 0);

        let fn_spend = Duration::from_millis(300);

        father1.spawn(async move {
            assert_eq!(father.task_count(), 2);
            let children1 = children.clone();
            children1.spawn(async move {
                assert_eq!(children.task_count(), 2);
                let grandson1 = grandson.clone();
                grandson1.spawn(async move {
                    assert_eq!(grandson.task_count(), 1);
                    println!("grandson sleep");
                    sleep(fn_spend).await;
                    println!("grandson wait");
                    grandson.cancel_all();
                    println!("grandson cancel");
                });
                assert_eq!(children.task_count(), 2);
                println!("children sleep");
                sleep(fn_spend).await;
                println!("children wait");
                grandson1.wait().await;
                println!("children wait done");
            });
            assert_eq!(father.task_count(), 2);
            println!("father sleep");
            sender.send(()).unwrap();
            sleep(fn_spend).await;
            println!("father wait");
            children1.wait().await;
            println!("father wait done");
        });

        receiver.await.unwrap();
        assert_eq!(father1.task_count(), 2);
        assert_eq!(children1.task_count(), 2);
        assert_eq!(grandson1.task_count(), 1);

        timeout(Duration::from_millis(400), grandson1.wait())
            .await
            .unwrap();

        assert!(grandson1.has_cancel());
        assert!(children1.has_cancel());
        assert!(father1.has_cancel());

        assert_eq!(grandson1.task_count(), 0);
        assert_eq!(children1.task_count(), 0);
        assert_eq!(father1.task_count(), 0);
    }

    #[tokio::test]
    async fn test_context_cancel() {
        let context = Context::default();
        let children = context.children();

        children.cancel();
        assert!(!context.has_cancel());
        assert!(children.has_cancel());
        assert_eq!(children.task_count(), 0);
        children.wait().await;

        context.cancel();
        assert!(context.has_cancel());
        context.wait().await;
        assert_eq!(context.task_count(), 0);
    }

    #[tokio::test]
    async fn test_context_cancel_children() {
        let context = Context::default();
        let children = context.children();

        context.cancel();
        assert!(context.has_cancel());
        assert!(children.has_cancel());
        children.wait().await;
        context.wait().await;
    }

    #[tokio::test]
    async fn test_context_timeout() {
        let context = Context::default();
        let err = context
            .timeout(Duration::from_secs(1), async {
                sleep(Duration::from_secs(2)).await;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(err.is_timeout());
    }
}
