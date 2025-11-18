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

use crate::errors::{Error, Result, whatever};

/// Reader for reading data from network streams.
///
/// This struct provides async methods for reading data from network connections,
/// with support for cancellation through the controller.
pub struct Reader {
    inner: ReadInner,
    display: String,
}

impl fmt::Display for Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

impl Reader {
    #[inline]
    pub async fn read(&mut self, controller: &Context, buf: &mut [u8]) -> Result<usize> {
        assert_ne!(buf.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
            r = self.inner.read(buf) => Ok(r?),
        }
    }
    #[inline]
    pub async fn read_exact(&mut self, controller: &Context, buf: &mut [u8]) -> Result<usize> {
        assert_ne!(buf.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
            r = self.inner.read_exact(buf) => Ok(r?),
        }
    }
}

/// Writer for writing data to network streams.
///
/// This struct provides async methods for writing data to network connections,
/// with support for cancellation through the controller.
pub struct Writer {
    inner: WriteInner,
    display: String,
}

impl fmt::Display for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display)
    }
}

impl Writer {
    #[inline]
    pub async fn write_all(&mut self, controller: &Context, data: &[u8]) -> Result<()> {
        assert_ne!(data.len(), 0);
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
            r = self.inner.write_all(data) => Ok(r?),
        }
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

/// A bidirectional network stream.
///
/// This struct represents a network connection with separate reader and writer halves,
/// allowing for concurrent reading and writing operations.
pub struct Stream {
    pub reader: Reader,
    pub writer: Writer,
}

impl fmt::Display for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reader.fmt(f)
    }
}

impl Stream {
    pub fn from_tcp_stream(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().unwrap();
        let peer_addr = stream.peer_addr().unwrap();
        let display = format!("{}-{}", local_addr, peer_addr);
        let (r, w) = stream.into_split();
        Stream {
            reader: Reader {
                inner: ReadInner::Tcp(r),
                display: display.clone(),
            },
            writer: Writer {
                inner: WriteInner::Tcp(w),
                display,
            },
        }
    }
}

/// Network listener for accepting incoming connections.
///
/// This enum represents different types of network listeners that can accept
/// incoming connections and create streams.
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
    pub async fn accept(&mut self, controller: &Context) -> Result<Stream> {
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
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
        }
    }
}

/// Network address representation.
///
/// This enum represents different types of network addresses that can be used
/// for connecting to or listening on network endpoints.
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
            .ok_or_else(|| whatever!("Invalid address {}", raw))?;

        Ok(Address::Tcp(addr))
    }

    pub async fn connect_to(&self, controller: &Context) -> Result<Stream> {
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
            r = self.connect_to_impl() => r,
        }
    }

    async fn connect_to_impl(&self) -> Result<Stream> {
        match self {
            Address::Tcp(a) => {
                let stream = TcpStream::connect(a).await?;
                set_keep_alive(&stream)?;
                Ok(Stream::from_tcp_stream(stream))
            }
        }
    }

    pub async fn listen_to(&self, controller: &Context) -> Result<Listener> {
        tokio::select! {
            _ = controller.wait_cancel() => Err(Error::cancel()),
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

fn set_keep_alive(stream: &TcpStream) -> Result<()> {
    let socket_ref = socket2::SockRef::from(stream);
    let keep_alive = TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(1));
    socket_ref.set_tcp_keepalive(&keep_alive)?;
    Ok(())
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

/// Context for managing async tasks and cancellation.
///
/// This struct provides facilities for spawning tasks, managing their lifecycle,
/// and coordinating cancellation across a hierarchy of tasks. It supports creating
/// child controllers that can be cancelled independently or as part of a parent.
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

    pub async fn timeout<T, F>(&self, duration: Duration, f: F) -> Result<T>
    where
        F: IntoFuture<Output = Result<T>>,
    {
        timeout(duration, f).await
    }

    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
    pub async fn timeout_default<T, F>(&self, f: F) -> Result<T>
    where
        F: IntoFuture<Output = Result<T>>,
    {
        timeout(Self::DEFAULT_TIMEOUT, f).await
    }
}

/// Executes a future with a timeout.
///
/// This function wraps a future and returns an error if it doesn't complete
/// within the specified duration.
///
/// # Arguments
///
/// * `duration` - The maximum time to wait for the future to complete
/// * `f` - The future to execute
///
/// # Returns
///
/// Returns the result of the future if it completes within the timeout.
///
/// # Errors
///
/// Returns a timeout error if the future doesn't complete within the specified duration.
pub async fn timeout<T, F>(duration: Duration, f: F) -> Result<T>
where
    F: IntoFuture<Output = Result<T>>,
{
    match tokio::time::timeout(duration, f).await {
        Ok(r) => r,
        Err(_) => Err(Error::from_timeout(duration)),
    }
}

#[cfg(test)]
mod tests {

    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    use super::*;

    #[tokio::test]
    async fn test_controller_children_wait() {
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
    async fn test_controller_cancel() {
        let controller = Context::default();
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
        let controller = Context::default();
        let children = controller.children();

        controller.cancel();
        assert!(controller.has_cancel());
        assert!(children.has_cancel());
        children.wait().await;
        controller.wait().await;
    }

    #[tokio::test]
    async fn test_controller_timeout() {
        let controller = Context::default();
        let err = controller
            .timeout(Duration::from_secs(1), async {
                sleep(Duration::from_secs(2)).await;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(err.is_timeout());
    }
}
