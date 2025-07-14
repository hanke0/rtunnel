use anyhow::Result;
use anyhow::anyhow;
use serde::de::{Deserialize, Deserializer, Visitor};
use std::fmt::Debug;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::result::Result::Ok;
use std::str::FromStr;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

pub struct Reader(Arc<Mutex<Stream>>);

impl Reader {
    pub async fn read(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.0.lock();
        guard.unwrap().read(buf).await
    }
    pub async fn read_exact(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.0.lock();
        guard.unwrap().read_exact(buf).await
    }
}

impl Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.0.lock();
        write!(f, "{}", guard.unwrap())
    }
}

pub struct Writer(Arc<Mutex<Stream>>);

impl Writer {
    pub async fn write_all(self: &mut Self, data: &[u8]) -> io::Result<()> {
        let guard = self.0.lock();
        guard.unwrap().write_all(data).await
    }
}

impl Display for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.0.lock();
        write!(f, "{}", guard.unwrap())
    }
}

pub enum Stream {
    TCP(TcpStream),
}

impl Stream {
    pub async fn write_all(self: &mut Self, data: &[u8]) -> io::Result<()> {
        match self {
            Stream::TCP(s) => s.write_all(data).await,
        }
    }
    pub async fn read(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::TCP(s) => s.read(buf).await,
        }
    }
    pub async fn read_exact(self: &mut Self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::TCP(s) => s.read_exact(buf).await,
        }
    }
    pub fn split(self) -> (Reader, Writer) {
        let a = Arc::new(Mutex::new(self));
        let b = a.clone();
        (Reader(a), Writer(b))
    }
}

impl Display for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stream::TCP(s) => {
                let addr = s.peer_addr().unwrap();
                write!(f, "{}", addr)
            }
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
                Ok((Stream::TCP(stream), addr))
            }
        }
    }
}

enum AddressType {
    TCP(SocketAddr),
    Invalid,
}

pub struct Address {
    raw: String,
    addr: AddressType,
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl Address {
    pub fn new() -> Self {
        Address {
            raw: "invalid".to_string(),
            addr: AddressType::Invalid,
        }
    }
    pub fn from_string(raw: &str) -> Result<Self> {
        if raw.starts_with("tcp://") {
            let raw = raw.strip_prefix("tcp://").unwrap();
            let addr = SocketAddr::from_str(raw)?;
            Ok(Address {
                raw: raw.to_string(),
                addr: AddressType::TCP(addr),
            })
        } else {
            let addr = SocketAddr::from_str(raw)?;
            Ok(Address {
                raw: raw.to_string(),
                addr: AddressType::TCP(addr),
            })
        }
    }

    pub async fn connect_to(&self) -> Result<Stream> {
        match self.addr {
            AddressType::TCP(a) => {
                let stream = TcpStream::connect(a).await?;
                Ok(Stream::TCP(stream))
            }
            AddressType::Invalid => Err(anyhow!("Invalid address")),
        }
    }

    pub async fn listen_to(&self) -> Result<Listener> {
        match self.addr {
            AddressType::TCP(a) => {
                let listener = TcpListener::bind(a).await?;
                Ok(Listener::TCP(listener))
            }
            AddressType::Invalid => Err(anyhow!("Invalid address")),
        }
    }
}

impl Visitor<'_> for Address {
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
        deserializer.deserialize_str(Address::new())
    }
}

struct Controller {
    shutdown: CancellationToken,
    active: AtomicI64,
}

struct DropGuard {
    controller: Arc<Controller>,
}
impl Drop for DropGuard {
    fn drop(&mut self) {
        self.controller.active.fetch_sub(1, Ordering::Release);
    }
}

impl Controller {
    fn new() -> Self {
        let shutdown = CancellationToken::new();
        let active = AtomicI64::new(0);
        Self { shutdown, active }
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
    }

    fn has_shutdown(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    pub fn drop_guard(&self) -> DropGuard {
        self.active.fetch_add(1, Ordering::Release);
        DropGuard {
            controller: Arc::new(self),
        }
    }

    async fn wait_shutdown(&self) {
        self.shutdown.cancelled().await
    }

    fn has_finished(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }

    async fn wait_finish(&self) {
        self.wait_shutdown().await;
        let tick = tokio::time::interval(Duration::from_millis(300));
        loop {
            if self.has_finished() {
                break;
            }
            tick.tick().await;
        }
    }

    async fn run_until_shutdown<F>(&self, fut: F) -> Option<F::Output>
    where
        F: Future,
    {
        let guard = self.drop_guard();
        self.shutdown.run_until_cancelled(fut).await
    }
}
