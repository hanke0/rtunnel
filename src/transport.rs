use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

use serde::de::{Deserialize, Deserializer, Visitor};
use socket2::TcpKeepalive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::anyerror;
use crate::errors::{self, Result, cancel_error, from_io_error};

pub struct Reader {
    inner: ReadInner,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl fmt::Display for Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.peer_addr(), self.local_addr())
    }
}

impl Reader {
    #[inline]
    pub async fn read(&mut self, controller: &Controller, buf: &mut [u8]) -> Result<usize> {
        assert_ne!(buf.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(cancel_error()),
            r = self.inner.read(buf) => r.map_err(from_io_error),
        }
    }
    #[inline]
    pub async fn read_exact(&mut self, controller: &Controller, buf: &mut [u8]) -> Result<usize> {
        assert_ne!(buf.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(cancel_error()),
            r = self.inner.read_exact(buf) => r.map_err(from_io_error),
        }
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

impl fmt::Display for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.peer_addr(), self.local_addr())
    }
}

impl Writer {
    #[inline]
    pub async fn write_all(&mut self, controller: &Controller, data: &[u8]) -> Result<()> {
        assert_ne!(data.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(cancel_error()),
            r = self.inner.write_all(data) => r.map_err(from_io_error),
        }
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
    Tcp(OwnedReadHalf),
}

impl ReadInner {
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ReadInner::Tcp(s) => s.read(buf).await,
        }
    }
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ReadInner::Tcp(s) => s.read_exact(buf).await,
        }
    }
}

enum WriteInner {
    Tcp(OwnedWriteHalf),
}

impl WriteInner {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            WriteInner::Tcp(s) => s.write_all(data).await,
        }
    }
}

pub struct Stream {
    pub reader: Reader,
    pub writer: Writer,
}

impl fmt::Display for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}",
            self.reader.peer_addr(),
            self.reader.local_addr()
        )
    }
}

impl Stream {
    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let (r, w) = stream.into_split();
        Stream {
            reader: Reader {
                inner: ReadInner::Tcp(r),
                local_addr,
                peer_addr,
            },
            writer: Writer {
                inner: WriteInner::Tcp(w),
                local_addr,
                peer_addr,
            },
        }
    }

    #[inline]
    #[allow(dead_code)]
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
    Tcp(TcpListener),
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Listener::Tcp(s) => {
                let addr = s.local_addr().unwrap();
                write!(f, "{}", addr)
            }
        }
    }
}

impl Listener {
    pub async fn accept(&mut self, controller: &Controller) -> Result<Stream> {
        tokio::select! {
            _ = controller.wait_cancel() => Err(cancel_error()),
            r = self.accept_impl() => r,
        }
    }

    async fn accept_impl(&mut self) -> Result<Stream> {
        match self {
            Listener::Tcp(s) => {
                let (stream, _) = s.accept().await?;
                let stream = set_keepalive(stream)?;
                Ok(Stream::from_tcp_stream(stream))
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum Address {
    Tcp(SocketAddr),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Tcp(a) => {
                write!(f, "tcp://{}", a)
            }
        }
    }
}

impl Address {
    pub fn as_string(&self) -> String {
        match self {
            Address::Tcp(a) => {
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
        let addr = iter
            .next()
            .ok_or_else(|| errors::anyerror!("Invalid address {}", raw))?;

        Ok(Address::Tcp(addr))
    }

    pub async fn connect_to(&self, controller: &Controller) -> Result<Stream> {
        tokio::select! {
            _ = controller.wait_cancel() => Err(cancel_error()),
            r = self.connect_to_impl() => r,
        }
    }

    async fn connect_to_impl(&self) -> Result<Stream> {
        match self {
            Address::Tcp(a) => {
                let stream = TcpStream::connect(a).await?;
                let stream = set_keepalive(stream)?;
                Ok(Stream::from_tcp_stream(stream))
            }
        }
    }

    pub async fn listen_to(&self, controller: &Controller) -> Result<Listener> {
        tokio::select! {
            _ = controller.wait_cancel() => {
                Err(cancel_error())
            }
            r = self.listen_to_impl() => r
        }
    }

    async fn listen_to_impl(&self) -> Result<Listener> {
        match self {
            Address::Tcp(a) => {
                let listener = TcpListener::bind(a).await?;
                Ok(Listener::Tcp(listener))
            }
        }
    }
}

fn set_keepalive(stream: TcpStream) -> Result<TcpStream> {
    let stream: std::net::TcpStream = stream.into_std().unwrap();
    let socket: socket2::Socket = socket2::Socket::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(1));
    socket.set_tcp_keepalive(&keepalive)?;
    let stream: std::net::TcpStream = socket.into();

    tokio::net::TcpStream::from_std(stream).map_err(from_io_error)
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
        deserializer.deserialize_str(AddressVisitor)
    }
}

pub struct Controller {
    cancel_token: CancellationToken,
    tracker: TaskTracker,
    father: Option<Box<Self>>,
}

impl Clone for Controller {
    fn clone(&self) -> Self {
        Self {
            cancel_token: self.cancel_token.clone(),
            tracker: self.tracker.clone(),
            father: self.father.clone(),
        }
    }
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            cancel_token: CancellationToken::new(),
            tracker: TaskTracker::new(),
            father: None,
        }
    }
}

impl Controller {
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
}

#[cfg(test)]
mod tests {

    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    use super::*;

    #[tokio::test]
    async fn test_controller_children_wait() {
        let father = Controller::default();
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
    async fn test_controller_cancel() {
        let controller = Controller::default();
        let children = controller.children();

        children.cancel();
        assert!(!controller.has_cancel());
        assert!(children.has_cancel());
        assert_eq!(children.task_count(), 0);
        children.wait().await;

        controller.cancel();
        assert!(controller.has_cancel());
        controller.wait().await;
        assert_eq!(controller.task_count(), 0);
    }

    #[tokio::test]
    async fn test_controller_cancel_children() {
        let controller = Controller::default();
        let children = controller.children();

        controller.cancel();
        assert!(controller.has_cancel());
        assert!(children.has_cancel());
        children.wait().await;
        controller.wait().await;
    }
}
