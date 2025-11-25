use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::{Pin, pin};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::task::Context as FContext;
use std::task::Poll;
use std::time::Duration;

use bytes::BytesMut;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use socket2::TcpKeepalive;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector as TokioTlsConnector;
use tokio_rustls::client::TlsStream as TlsClientStream;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::server::ServerSessionMemoryCache;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::server::TlsStream as TlsServerStream;
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;
use tracing::warn;

use crate::errors::{Error, Result, ResultExt as _, ToAny as _, whatever};

pub use tokio::net::TcpListener;

#[inline]
pub async fn relay_bidirectional<A, B>(mut a: A, mut b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Sized,
    B: AsyncRead + AsyncWrite + Unpin + Sized,
{
    Ok(tokio::io::copy_bidirectional(&mut a, &mut b).await?)
}

pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl Stream for TcpStream {}
impl Stream for TlsServerStream<TcpStream> {}
impl Stream for TlsClientStream<TcpStream> {}
impl Stream for QuinStream {}

pub trait Listener: Sized + Send + Sync + Display + Debug + 'static {
    type Stream: Stream;
    type Config;

    fn new(config: Self::Config) -> impl Future<Output = Result<Self>> + Send + Sync;
    fn accept(&self) -> impl Future<Output = Result<(Self::Stream, String)>> + Send + Sync;
    fn address(&self) -> SocketAddr;
}

pub trait Connector: Sized + Send + Sync + Display + Debug + 'static {
    type Stream: Stream;
    type Config;

    fn new(config: Self::Config) -> impl Future<Output = Result<Self>> + Send;
    fn connect(&self) -> impl Future<Output = Result<(Self::Stream, String)>> + Send;
    fn address(&self) -> SocketAddr;
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TlsTcpListenerConfig {
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub subject: String,
    pub addr: SocketAddr,
}

pub struct TlsTcpListener {
    acceptor: TlsAcceptor,
    listener: TcpListener,
    addr: SocketAddr,
}

impl fmt::Display for TlsTcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tls://{}", self.addr)
    }
}

impl fmt::Debug for TlsTcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TlsListener({})", self.addr)
    }
}

impl Listener for TlsTcpListener {
    type Stream = TlsServerStream<TcpStream>;
    type Config = TlsTcpListenerConfig;

    async fn new(config: Self::Config) -> Result<Self> {
        let server_config =
            build_tls_server_config(&config.server_cert, &config.server_key, &config.client_cert)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(config.addr).await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            acceptor,
            listener,
            addr,
        })
    }

    async fn accept(&self) -> Result<(Self::Stream, String)> {
        let (stream, _) = self.listener.accept().await?;
        socket_hint(&stream);
        let local_addr = stream.local_addr()?.to_string();
        let peer_addr = stream.peer_addr()?.to_string();
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(Error::from_tls)?;
        Ok((stream, format!("{}-{}", local_addr, peer_addr)))
    }

    fn address(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PlainTcpListenerConfig {
    pub addr: SocketAddr,
}

pub struct PlainTcpListener {
    listener: TcpListener,
    addr: SocketAddr,
}

impl fmt::Display for PlainTcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tcp://{}", self.addr)
    }
}

impl Debug for PlainTcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainTcpListener({})", self.addr)
    }
}

impl Listener for PlainTcpListener {
    type Stream = TcpStream;
    type Config = PlainTcpListenerConfig;

    async fn new(config: Self::Config) -> Result<Self> {
        let listener = TcpListener::bind(config.addr).await?;
        let addr = listener.local_addr()?;
        Ok(Self { listener, addr })
    }

    async fn accept(&self) -> Result<(Self::Stream, String)> {
        let (stream, _) = self.listener.accept().await?;
        socket_hint(&stream);
        let local_addr = stream.local_addr()?.to_string();
        let peer_addr = stream.peer_addr()?.to_string();
        Ok((stream, format!("{}-{}", local_addr, peer_addr)))
    }

    fn address(&self) -> SocketAddr {
        self.addr
    }
}

pub struct QuicListenerConfig {
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub subject: String,
    pub addr: SocketAddr,
}

pub struct QuicListener {
    endpoint: Endpoint,
    addr: SocketAddr,
}

impl Listener for QuicListener {
    type Stream = QuinStream;
    type Config = QuicListenerConfig;

    async fn new(config: Self::Config) -> Result<Self> {
        let server_config =
            build_tls_server_config(&config.server_cert, &config.server_key, &config.client_cert)?;
        let server_config = QuicServerConfig::try_from(server_config).to_any()?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0_u8.into());

        let addr = config.addr;
        let endpoint = Endpoint::server(server_config, config.addr)?;
        Ok(Self { endpoint, addr })
    }

    async fn accept(&self) -> Result<(Self::Stream, String)> {
        let incoming = match self.endpoint.accept().await {
            Some(incoming) => incoming,
            None => return Err(Error::eof("quic listener closed")),
        };
        let connection = incoming.await.to_any()?;
        let (send, recv) = connection.accept_bi().await.to_any()?;
        let peer_addr = connection.remote_address();
        Ok((
            QuinStream(send, recv),
            format!("{}-{}", self.addr, peer_addr),
        ))
    }

    fn address(&self) -> SocketAddr {
        self.addr
    }
}

impl Display for QuicListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "quic://{}", self.addr)
    }
}

impl Debug for QuicListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuicListener({})", self.addr)
    }
}

pub struct QuinStream(SendStream, RecvStream);

impl AsyncRead for QuinStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut FContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        pin!(&mut self.1).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut FContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        pin!(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut FContext<'_>) -> Poll<std::io::Result<()>> {
        pin!(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut FContext<'_>) -> Poll<std::io::Result<()>> {
        pin!(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct TlsTcpConnectorConfig {
    pub client_cert: String,
    pub client_key: String,
    pub server_cert: String,
    pub subject: String,
    pub addr: String,
}

pub struct TlsTcpConnector {
    connector: TokioTlsConnector,
    addr: SocketAddr,
    server_name: ServerName<'static>,
}

impl fmt::Display for TlsTcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tls://{}", self.addr)
    }
}

impl fmt::Debug for TlsTcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TlsConnector({})", self.addr)
    }
}

impl Connector for TlsTcpConnector {
    type Stream = TlsClientStream<TcpStream>;
    type Config = TlsTcpConnectorConfig;

    async fn new(config: Self::Config) -> Result<Self> {
        let addr = config
            .addr
            .to_socket_addrs()?
            .next()
            .ok_or(whatever!("Invalid address"))?;
        let client_config =
            build_tls_client_config(&config.client_cert, &config.client_key, &config.server_cert)?;
        let server_name =
            ServerName::try_from(config.subject).context("Failed to parse server name")?;
        let connector = TokioTlsConnector::from(Arc::new(client_config));
        Ok(Self {
            connector,
            addr,
            server_name,
        })
    }

    async fn connect(&self) -> Result<(Self::Stream, String)> {
        let stream = TcpStream::connect(self.addr).await?;
        let local_addr = stream.local_addr()?.to_string();
        let peer_addr = stream.peer_addr()?.to_string();
        socket_hint(&stream);
        let addr = stream.local_addr()?.to_string();
        let r = self
            .connector
            .connect(self.server_name.clone(), stream)
            .instrument(tracing::info_span!("client {}", addr))
            .await?;
        Ok((r, format!("{}-{}", local_addr, peer_addr)))
    }

    fn address(&self) -> SocketAddr {
        self.addr
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PlainTcpConnectorConfig {
    pub addr: String,
}

pub struct PlainTcpConnector {
    addr: SocketAddr,
}

impl fmt::Display for PlainTcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tcp://{}", self.addr)
    }
}

impl fmt::Debug for PlainTcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlainTcpConnector({})", self.addr)
    }
}

impl Connector for PlainTcpConnector {
    type Stream = TcpStream;
    type Config = PlainTcpConnectorConfig;

    async fn new(config: Self::Config) -> Result<Self> {
        let addr = config
            .addr
            .to_socket_addrs()?
            .next()
            .ok_or(whatever!("Invalid address"))?;
        Ok(Self { addr })
    }

    async fn connect(&self) -> Result<(Self::Stream, String)> {
        let stream = TcpStream::connect(self.addr).await?;
        let local_addr = stream.local_addr()?.to_string();
        let peer_addr = stream.peer_addr()?.to_string();
        socket_hint(&stream);
        Ok((stream, format!("{local_addr}-{peer_addr}")))
    }

    fn address(&self) -> SocketAddr {
        self.addr
    }
}

pub enum Transport {
    Tcp(SocketAddr),
}

impl Transport {
    pub fn parse(value: &str) -> Result<Self> {
        if value.starts_with("tcp://") {
            let addr = value.strip_prefix("tcp://").unwrap();
            let addr = addr
                .to_socket_addrs()?
                .next()
                .ok_or(whatever!("Invalid address"))?;
            Ok(Transport::Tcp(addr))
        } else {
            let addr = value
                .to_socket_addrs()?
                .next()
                .ok_or(whatever!("Invalid address"))?;
            Ok(Transport::Tcp(addr))
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Transport::Tcp(addr) => format!("tcp://{}", addr),
        }
    }
}

pub fn tcp_no_delay(stream: &TcpStream) {
    socket_hint_impl(stream, true, false);
}

fn socket_hint(stream: &TcpStream) {
    socket_hint_impl(stream, true, true);
}

fn socket_hint_impl(stream: &TcpStream, no_delay: bool, keep_alive: bool) {
    let socket_ref = socket2::SockRef::from(stream);
    if no_delay {
        socket_ref.set_tcp_nodelay(true).suppress(|err| {
            warn!("set_tcp_nodelay failed: {}", err);
        });
    }
    if keep_alive {
        static KEEP_ALIVE: TcpKeepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(10))
            .with_interval(Duration::from_secs(1));
        socket_ref.set_tcp_keepalive(&KEEP_ALIVE).suppress(|err| {
            warn!("set_tcp_keepalive failed: {}", err);
        });
    }
}

fn build_tls_server_config(
    server_cert: &str,
    server_key: &str,
    client_cert: &str,
) -> Result<rustls::ServerConfig> {
    let cert_chain = CertificateDer::from_pem_slice(server_cert.as_bytes())
        .context("Failed to parse server cert")?;
    let key_der = PrivateKeyDer::from_pem_slice(server_key.as_bytes())
        .context("Failed to parse server key")?;
    let client_ca = CertificateDer::from_pem_slice(client_cert.as_bytes())
        .context("Failed to parse client ca")?;
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(client_ca)
        .context("failed to add client ca to root store")?;
    let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("Failed to build client cert verifier")?;
    debug_assert!(client_cert_verifier.client_auth_mandatory());
    debug_assert!(client_cert_verifier.offer_client_auth());
    let mut server_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(vec![cert_chain], key_der)
            .context("Failed to build server tls config")?;
    server_config.ignore_client_order = true;
    server_config.session_storage = ServerSessionMemoryCache::new(256);
    Ok(server_config)
}

fn build_tls_client_config(
    client_cert: &str,
    client_key: &str,
    server_cert: &str,
) -> Result<rustls::ClientConfig> {
    let cert_chain = CertificateDer::from_pem_slice(client_cert.as_bytes())
        .context("Failed to parse client cert")?;
    let key_der = PrivateKeyDer::from_pem_slice(client_key.as_bytes())
        .context("Failed to parse client key")?;
    let server_cert = CertificateDer::from_pem_slice(server_cert.as_bytes())
        .context("Failed to parse server cert")?;
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(server_cert)
        .context("Failed to add server cert to root store")?;

    let mut client_config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![cert_chain], key_der)
            .context("Failed to build client tls config")?;
    client_config.enable_sni = false;
    client_config.resumption = Resumption::in_memory_sessions(256);
    Ok(client_config)
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
        E: Into<Error>,
    {
        timeout(duration, f).await
    }

    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
    pub async fn timeout_default<T, E, F>(&self, f: F) -> Result<T>
    where
        F: IntoFuture<Output = StdResult<T, E>>,
        E: Into<Error>,
    {
        timeout(Self::DEFAULT_TIMEOUT, f).await
    }

    /// race runs futures and fast kill it if context is cancelled.
    /// It returns first result or [`Error::cancel()`]
    ///
    /// [`Error::cancel()`]: crate::errors::Error::cancel
    #[inline]
    pub async fn race<T, E, F>(&self, f: F) -> Result<T>
    where
        F: IntoFuture<Output = StdResult<T, E>>,
        E: Into<Error>,
    {
        tokio::select! {
            r = f => {
                match r {
                        Ok(r) => Ok(r),
                        Err(e) => Err(e.into()),
                }
            }
            _ = self.wait_cancel() => Err(Error::cancel()),
        }
    }
}

/// Executes a future with a timeout.
pub async fn timeout<T, E, F>(duration: Duration, f: F) -> Result<T>
where
    F: IntoFuture<Output = StdResult<T, E>>,
    E: Into<Error>,
{
    match tokio::time::timeout(duration, f).await {
        Ok(r) => match r {
            Ok(r) => Ok(r),
            Err(e) => Err(e.into()),
        },
        Err(_) => Err(Error::from_timeout(duration)),
    }
}

/// Message type enumeration for tunnel protocol messages.
///
/// This enum represents the different types of messages that can be sent
/// over the encrypted tunnel connection.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum MessageKind {
    Connect,
    Ping,
    Require,
}

impl MessageKind {
    const REQUIRE: u8 = 0b01000000;
    const CONNECT: u8 = 0b10000000;
    const PING: u8 = 0b11000000;
    const _RESERVED: u8 = 0b00000000;

    fn from_checked_u8(msg_type: u8) -> Self {
        Self::from_u8(msg_type).unwrap()
    }

    fn from_u8(msg_type: u8) -> Result<Self> {
        match msg_type {
            Self::REQUIRE => Ok(MessageKind::Require),
            Self::CONNECT => Ok(MessageKind::Connect),
            Self::PING => Ok(MessageKind::Ping),
            _ => Err(whatever!("Invalid message type: {}", msg_type)),
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            MessageKind::Require => Self::REQUIRE,
            MessageKind::Connect => Self::CONNECT,
            MessageKind::Ping => Self::PING,
        }
    }
}

#[cfg(test)]
mod test_message_kind {
    use super::MessageKind;

    #[test]
    fn test_message_kind() {
        macro_rules! ensure_exhaustive {
            ($E:path, $($variant:ident),*) => {
                {
                    use $E as E;
                    let variants = [$(E::$variant),*];
                    for variant in variants {
                        match variant {
                            $(E::$variant => {
                                let got = E::from_u8(E::$variant.as_u8()).unwrap();
                                assert_eq!(got, E::$variant);
                            }),*
                        }
                    }
                }
            }
        }
        ensure_exhaustive!(MessageKind, Connect, Ping, Require);
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
        message.set_header(MessageKind::Ping, 0);
        message
    }

    pub fn connect(addr: &str) -> Self {
        let mut message = Self::with_capacity(addr.len());
        message.connect_inplace(addr);
        message
    }

    pub fn connect_inplace(&mut self, addr: &str) {
        self.fill(MessageKind::Connect, |buf| {
            buf.extend_from_slice(addr.as_bytes());
        });
    }

    pub fn require(n: i32) -> Self {
        let mut message = Self::with_capacity(4);
        message.fill(MessageKind::Require, |buf| {
            buf.extend_from_slice(&n.to_be_bytes());
        });
        message
    }

    pub fn parse_require(&self) -> Result<i32> {
        let bytes = <[u8; 4]>::try_from(self.get_payload()).context("Invalid require message")?;
        Ok(i32::from_be_bytes(bytes))
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut buf = BytesMut::with_capacity(capacity + Self::HEADER_SIZE);
        buf.resize(Self::HEADER_SIZE, 0);
        let mut message = Message(buf);
        message.set_header(MessageKind::Ping, 0);
        message
    }

    pub fn get_type(&self) -> MessageKind {
        MessageKind::from_checked_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    fn get_unchecked_type(&self) -> Result<MessageKind> {
        MessageKind::from_u8(self.0[0] & Self::MSG_TYPE_FLAG)
    }

    pub fn get_payload_size(&self) -> usize {
        u16::from_be_bytes([self.0[0] & Self::DATA_SIZE_HIGH_FLAG, self.0[1]]) as usize
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.0[Self::HEADER_SIZE..]
    }

    fn set_header(&mut self, msg_type: MessageKind, body_size: usize) {
        let high = (body_size >> 8) as u8;
        let low = (body_size & 0xff) as u8;
        let buf = &mut self.0;
        assert!(buf.len() > 1);
        buf[0] = high | msg_type.as_u8();
        buf[1] = low;
    }

    pub fn fill<O, F: FnOnce(&mut BytesMut) -> O>(&mut self, message_type: MessageKind, f: F) -> O {
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

    pub async fn read_from<T: Stream>(stream: &mut T) -> Result<Self> {
        let mut msg = Self::default();
        msg.read_from_inplace(stream).await?;
        Ok(msg)
    }

    pub async fn write_to<T: Stream>(&self, stream: &mut T) -> Result<()> {
        stream.write_all(self.as_ref()).await?;
        Ok(())
    }

    pub async fn read_from_inplace<T: Stream>(&mut self, stream: &mut T) -> Result<()> {
        self.0.resize(Self::HEADER_SIZE, 0);
        stream
            .read_exact(&mut self.0)
            .await
            .context("Failed to read message header from stream")?;
        self.get_unchecked_type()?;
        let mut payload = self.0.split_off(Self::HEADER_SIZE);
        payload.resize(self.get_payload_size(), 0);
        if payload.is_empty() {
            return Ok(());
        }
        stream
            .read_exact(&mut payload)
            .await
            .context("Failed to read message from stream")?;
        self.0.unsplit(payload);
        Ok(())
    }

    pub async fn wait_connect_message<T: Stream, F>(
        &mut self,
        context: &Context,
        stream: &mut T,
        mut handle_other: F,
    ) -> Result<String>
    where
        F: AsyncFnMut(&Message) -> Result<()>,
    {
        loop {
            tokio::select! {
                _ = context.wait_cancel() => {
                    return Err(Error::cancel());
                }
                r = self.read_from_inplace::<T>(stream) => {
                    r?;
                }
            }
            match self.get_type() {
                MessageKind::Ping => {
                    stream.write_all(self.as_ref()).await?;
                    continue;
                }
                MessageKind::Connect => {
                    let addr = String::from_utf8(self.get_payload().to_vec())
                        .context("Invalid address")?;
                    return Ok(addr);
                }
                MessageKind::Require => {
                    handle_other(self).await?;
                    continue;
                }
            }
        }
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::with_capacity(1024 - Self::HEADER_SIZE)
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    use crate::observe;

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
                Result::<()>::Err(Error::cancel())
            })
            .await
            .unwrap_err();
        assert!(err.is_timeout());
    }

    use crate::config;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tracing::trace;

    #[tokio::test]
    async fn test_tls_stream() {
        observe::setup_testing();
        let cert = config::SelfSignedCert::new("example.com");
        let listener = TlsTcpListener::new(TlsTcpListenerConfig {
            server_cert: cert.server_cert.clone(),
            server_key: cert.server_key,
            client_cert: cert.client_cert.clone(),
            subject: cert.subject.clone(),
            addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        })
        .await
        .unwrap();
        let connector = TlsTcpConnector::new(TlsTcpConnectorConfig {
            subject: cert.subject,
            addr: listener.address().to_string(),
            client_cert: cert.client_cert,
            client_key: cert.client_key,
            server_cert: cert.server_cert,
        })
        .await
        .unwrap();
        let (client, server) = tokio::join!(connector.connect(), listener.accept(),);

        let ((mut send, ..), (mut recv, ..)) = (client.unwrap(), server.unwrap());
        send.write_all(b"hello").await.unwrap();
        let mut buf = [0; b"hello".len()];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"hello");
    }

    #[tokio::test]
    async fn test_tls_stream_client_auth_fail() {
        observe::setup_testing();
        let cert = config::SelfSignedCert::new("example.com");
        let cert1 = config::SelfSignedCert::new("example.com");

        let listener = TlsTcpListener::new(TlsTcpListenerConfig {
            server_cert: cert.server_cert.clone(),
            server_key: cert.server_key,
            client_cert: cert1.client_cert.clone(),
            subject: cert.subject.clone(),
            addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        })
        .await
        .unwrap();
        let connector = TlsTcpConnector::new(TlsTcpConnectorConfig {
            subject: cert.subject,
            addr: listener.address().to_string(),
            client_cert: cert.client_cert,
            client_key: cert.client_key,
            server_cert: cert.server_cert,
        })
        .await
        .unwrap();
        let (client, server) = tokio::join!(connector.connect(), listener.accept(),);

        let server_msg = server.expect_err("server should be error").to_string();
        trace!("server fail message: {:?}", server_msg);
        assert!(
            server_msg.contains("invalid peer certificate"),
            "{}",
            server_msg
        );

        // With a TLS 1.3 handshake connector.connect(..).await returns Ok
        // when the server aborts the connection with a fatal alert
        // after the client's Finished message.
        // The handshake failure error is only surfaced after a subsequent
        // read on the returned TlsStream.
        // With a TLS 1.2 handshake, connector.connect(..).await
        // returns Err when the server aborts the connection with the same alert.
        // https://github.com/rustls/rustls/issues/1707
        client.unwrap().0.read(&mut [0u8, 1]).await.unwrap_err();
    }

    #[tokio::test]
    async fn test_tls_stream_bad_server_cert() {
        observe::setup_testing();
        let cert = config::SelfSignedCert::new("example.com");
        let cert1 = config::SelfSignedCert::new("example.com");
        let listener = TlsTcpListener::new(TlsTcpListenerConfig {
            server_cert: cert.server_cert.clone(),
            server_key: cert.server_key,
            client_cert: cert.client_cert.clone(),
            subject: cert.subject.clone(),
            addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        })
        .await
        .unwrap();
        let connector = TlsTcpConnector::new(TlsTcpConnectorConfig {
            subject: cert.subject,
            addr: listener.address().to_string(),
            client_cert: cert.client_cert,
            client_key: cert.client_key,
            server_cert: cert1.server_cert,
        })
        .await
        .unwrap();
        let (client, server) = tokio::join!(connector.connect(), listener.accept(),);

        let server_msg = server.expect_err("server should be error").to_string();
        let client_msg = client.expect_err("client should be error").to_string();
        trace!("server fail message: {:?}", server_msg);
        trace!("client fail message: {:?}", client_msg);
        assert!(
            server_msg.contains("received fatal alert: DecryptError"),
            "{}",
            server_msg
        );
        assert!(
            client_msg.contains("invalid peer certificate: BadSignature"),
            "{}",
            client_msg
        );
    }
}
