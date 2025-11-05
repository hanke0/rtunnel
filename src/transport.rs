use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::result::Result::Ok;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use log::error;
use serde::de::{Deserialize, Deserializer, Visitor};
use socket2;
use socket2::TcpKeepalive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub struct Reader {
    inner: ReadInner,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl Reader {
    #[inline]
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).await
    }
    #[inline]
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_exact(buf).await
    }
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

pub struct Writer {
    inner: WriteInner,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl Writer {
    #[inline]
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_all(data).await
    }
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

enum ReadInner {
    TCP(OwnedReadHalf),
}

impl ReadInner {
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ReadInner::TCP(s) => s.read(buf).await,
        }
    }
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ReadInner::TCP(s) => s.read_exact(buf).await,
        }
    }
}

enum WriteInner {
    TCP(OwnedWriteHalf),
}

impl WriteInner {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WriteInner::TCP(s) => s.write_all(data).await,
        }
    }
}

pub struct Stream {
    pub reader: Reader,
    pub writer: Writer,
}

impl Stream {
    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let (r, w) = stream.into_split();
        Stream {
            reader: Reader {
                inner: ReadInner::TCP(r),
                local_addr,
                peer_addr,
            },
            writer: Writer {
                inner: WriteInner::TCP(w),
                local_addr,
                peer_addr,
            },
        }
    }

    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.reader.peer_addr
    }

    #[inline]
    #[allow(dead_code)]
    pub fn local_addr(&self) -> SocketAddr {
        self.reader.local_addr
    }
}

pub enum Listener {
    TCP(TcpListener),
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listener::TCP(s) => {
                let addr = s.local_addr().unwrap();
                write!(f, "{}", addr)
            }
        }
    }
}

impl Listener {
    pub async fn accept(self: &mut Self) -> io::Result<(Stream, SocketAddr)> {
        match self {
            Listener::TCP(s) => {
                let (stream, addr) = s.accept().await?;
                let stream = set_keepalive(stream)?;
                Ok((Stream::from_tcp_stream(stream), addr))
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub enum Address {
    TCP(SocketAddr),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::TCP(a) => {
                write!(f, "tcp://{}", a)
            }
        }
    }
}

impl Address {
    pub fn as_string(&self) -> String {
        match self {
            Address::TCP(a) => {
                format!("tcp://{}", a)
            }
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let raw = String::from_utf8(data.to_vec())?;
        Address::from_string(&raw)
    }

    pub fn from_string(raw: &str) -> Result<Self> {
        let mut iter = if raw.starts_with("tcp://") {
            raw.strip_prefix("tcp://").unwrap()
        } else {
            raw
        }
        .to_socket_addrs()?;
        let addr = iter.next().ok_or(anyhow!("Invalid address"))?;

        Ok(Address::TCP(addr))
    }

    pub async fn connect_to(&self) -> Result<Stream> {
        match self {
            Address::TCP(a) => {
                let stream = TcpStream::connect(a).await?;
                let stream = set_keepalive(stream)?;
                Ok(Stream::from_tcp_stream(stream))
            }
        }
    }

    pub async fn listen_to(&self) -> Result<Listener> {
        match self {
            Address::TCP(a) => {
                let listener = TcpListener::bind(a)
                    .await
                    .context(format!("Failed to bind {}", a))?;
                Ok(Listener::TCP(listener))
            }
        }
    }
}

fn set_keepalive(stream: TcpStream) -> io::Result<TcpStream> {
    let stream: std::net::TcpStream = stream.into_std().unwrap();
    let socket: socket2::Socket = socket2::Socket::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(1));
    socket.set_tcp_keepalive(&keepalive)?;
    let stream: std::net::TcpStream = socket.into();

    tokio::net::TcpStream::from_std(stream)
}

struct AddressVisitor;

impl Default for AddressVisitor {
    fn default() -> Self {
        AddressVisitor
    }
}

impl Visitor<'_> for AddressVisitor {
    // The type that our Visitor is going to produce.
    type Value = Address;

    // Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("tcp://127.0.0.1 or 127.0.0.1")
    }

    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match Address::from_string(v) {
            Ok(v) => Ok(v),
            Err(e) => Err(E::custom(e)),
        }
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(AddressVisitor::default())
    }
}

pub struct Controller {
    inner: Arc<ControllerInner>,
}

impl Clone for Controller {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum NotifyEvent {
    Shutdown,
    RelayStart,
    RelayFinish,
}

pub type Receiver = UnboundedReceiver<NotifyEvent>;

pub fn create_controller() -> (Controller, Receiver) {
    let shutdown = CancellationToken::new();
    let tracker = TaskTracker::new();
    let (sender, receiver) = unbounded_channel();
    let controller = Controller {
        inner: Arc::new(ControllerInner {
            shutdown,
            tracker,
            sender,
        }),
    };
    (controller, receiver)
}

pub struct ControllerGuard {
    controller: Controller,
    event: NotifyEvent,
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        self.controller.notify(self.event);
    }
}

impl Controller {
    pub fn children(&self) -> (Self, Receiver) {
        let (inner, receiver) = self.inner.children();
        (
            Self {
                inner: Arc::new(inner),
            },
            receiver,
        )
    }

    #[inline]
    pub fn spawn<F>(&self, task: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.tracker.spawn(task)
    }

    #[inline]
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
        self.inner.tracker.close();
    }

    #[inline]
    pub fn has_shutdown(&self) -> bool {
        self.inner.shutdown.is_cancelled()
    }

    pub fn notify(&self, ev: NotifyEvent) {
        match self.inner.sender.send(ev) {
            Ok(_) => (),
            Err(e) => {
                error!("send error: {}", e);
            }
        }
    }

    pub fn session_guard(&self) -> ControllerGuard {
        ControllerGuard {
            controller: self.clone(),
            event: NotifyEvent::Shutdown,
        }
    }

    pub fn relay_guard(&self) -> ControllerGuard {
        self.notify(NotifyEvent::RelayStart);
        ControllerGuard {
            controller: self.clone(),
            event: NotifyEvent::RelayFinish,
        }
    }

    #[inline]
    pub async fn wait(&self) {
        self.inner.tracker.wait().await;
    }

    #[inline]
    pub async fn wait_shutdown(&self) {
        self.inner.shutdown.cancelled().await;
    }

    #[inline]
    pub fn task_count(&self) -> usize {
        self.inner.tracker.len()
    }
}

struct ControllerInner {
    shutdown: CancellationToken,
    tracker: TaskTracker,
    sender: UnboundedSender<NotifyEvent>,
}

impl ControllerInner {
    fn children(&self) -> (Self, Receiver) {
        let (sender, receiver) = unbounded_channel();
        let controller = Self {
            shutdown: self.shutdown.clone(),
            tracker: self.tracker.clone(),
            sender,
        };
        (controller, receiver)
    }
}
