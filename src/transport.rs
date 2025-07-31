use anyhow::Result;
use anyhow::anyhow;
use serde::de::{Deserialize, Deserializer, Visitor};
use std::cmp;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::result::Result::Ok;
use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Stream {
    inner: Arc<Mutex<StreamInner>>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl Stream {
    fn new(stream: StreamInner) -> Self {
        let local_addr = stream.local_addr();
        let peer_addr = stream.peer_addr();
        let inner = Arc::new(Mutex::new(stream));
        Self {
            inner,
            local_addr,
            peer_addr,
        }
    }
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let mut guard = self.inner.lock().await;
        guard.write_all(data).await
    }
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self.inner.lock().await;
        guard.read(buf).await
    }
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self.inner.lock().await;
        guard.read_exact(buf).await
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Display for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.local_addr(), self.peer_addr())
    }
}

impl Ord for Stream {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let ord = self.peer_addr().cmp(&other.peer_addr());
        if ord.is_eq() {
            self.local_addr.cmp(&other.local_addr())
        } else {
            ord
        }
    }
}

impl PartialOrd for Stream {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Stream {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Stream {}

enum StreamInner {
    TCP(TcpStream),
}

impl StreamInner {
    pub async fn write_all(self: &mut Self, data: &[u8]) -> io::Result<()> {
        match self {
            StreamInner::TCP(s) => s.write_all(data).await,
        }
    }
    pub async fn read(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            StreamInner::TCP(s) => s.read(buf).await,
        }
    }
    pub async fn read_exact(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            StreamInner::TCP(s) => s.read_exact(buf).await,
        }
    }
    pub fn peer_addr(&self) -> SocketAddr {
        match self {
            StreamInner::TCP(s) => s.peer_addr().unwrap(),
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            StreamInner::TCP(s) => s.local_addr().unwrap(),
        }
    }
}

pub enum Listener {
    TCP(TcpListener),
}

impl Display for Listener {
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
                Ok((Stream::new(StreamInner::TCP(stream)), addr))
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub enum Address {
    TCP(SocketAddr),
}

impl Display for Address {
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
                Ok(Stream::new(StreamInner::TCP(stream)))
            }
        }
    }

    pub async fn listen_to(&self) -> Result<Listener> {
        match self {
            Address::TCP(a) => {
                let listener = TcpListener::bind(a).await?;
                Ok(Listener::TCP(listener))
            }
        }
    }
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

struct ControllerInner {
    shutdown: CancellationToken,
    active: AtomicI64,
}

impl Clone for Controller {
    fn clone(&self) -> Self {
        self.inner.active.fetch_add(1, Ordering::Release);
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(-1, Ordering::Release);
    }
}

impl Controller {
    fn new() -> Self {
        let shutdown = CancellationToken::new();
        let active = AtomicI64::new(0);
        Self {
            inner: Arc::new(ControllerInner { shutdown, active }),
        }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    pub fn has_shutdown(&self) -> bool {
        self.inner.shutdown.is_cancelled()
    }

    pub fn drop_guard(&self) -> Self {
        self.clone()
    }

    pub async fn wait_shutdown(&self) {
        self.inner.shutdown.cancelled().await
    }

    fn has_finish(&self) -> bool {
        self.inner.active.load(Ordering::Acquire) == 0
    }

    pub async fn wait(&self) {
        let mut tick = tokio::time::interval(Duration::from_millis(300));
        loop {
            if self.has_finish() {
                break;
            }
            tick.tick().await;
        }
    }

    async fn run_until_shutdown<F>(&self, fut: F) -> Option<F::Output>
    where
        F: Future,
    {
        let _guard = self.drop_guard();
        self.inner.shutdown.run_until_cancelled(fut).await
    }
}
