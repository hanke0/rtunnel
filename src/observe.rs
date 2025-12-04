use std::collections::BTreeMap;
use std::convert::Infallible;
use std::env;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use hyper::Method;
use hyper::Request;
use hyper::Response;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::warn;

use crate::errors::{Result, ResultExt as _};
use crate::transport::Context;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum Level {
    Trace,
    Debug,
    Info,
    #[default]
    Warn,
    Error,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Trace => write!(f, "trace"),
            Level::Debug => write!(f, "debug"),
            Level::Info => write!(f, "info"),
            Level::Warn => write!(f, "warn"),
            Level::Error => write!(f, "error"),
        }
    }
}

pub fn setup(log_level: Level) -> Result<()> {
    setup_impl(log_level, false)
}

pub fn setup_testing() {
    let _ = setup_impl(Level::Trace, true);
}

fn setup_impl(log_level: Level, is_testing: bool) -> Result<()> {
    let env_log = env::var("RUST_LOG").unwrap_or_default();
    let rust_log = if env_log.is_empty() {
        log_level.to_string() + ",quinn=off,quinn_proto=off,rustls=off,tokio_rustls=off"
    } else {
        env_log
    };
    let filter = tracing_subscriber::EnvFilter::new(rust_log);
    let builder = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter);
    if is_testing {
        builder
            .with_test_writer()
            .try_init()
            .context("Failed to init test logger")
    } else {
        builder.try_init().context("Failed to init logger")
    }
}

pub struct Watcher {
    watchs: Arc<Mutex<BTreeMap<String, WatchOne>>>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Watcher {
    fn clone(&self) -> Self {
        Self {
            watchs: self.watchs.clone(),
        }
    }
}

macro_rules! format_json {
    ($json:ident, $key1:literal: $value1:expr, $($key:literal: $value:expr),* $(,)?) => {
        $json.push('{');
        $json.push('\"');
        $json.push_str($key1);
        $json.push('\"');
        $json.push(':');
        $json.push_str(&$value1.to_string());
        $(
            $json.push(',');
            $json.push('\"');
            $json.push_str($key);
            $json.push('\"');
            $json.push(':');
            $json.push_str(&$value.to_string());
        )*
        $json.push('}');
    };
}

impl Watcher {
    pub fn new() -> Self {
        Self {
            watchs: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn watch(&self, name: String) -> WatchOne {
        let watch = WatchOne::new();
        self.watchs.lock().await.insert(name, watch.clone());
        watch
    }

    pub async fn serve_http(
        self,
        context: Context,
        listener: TcpListener,
        path: String,
    ) -> Result<()> {
        let service = HyperService { watch: self, path };
        loop {
            let (stream, _) = context.with_cancel(listener.accept()).await?;
            tokio::spawn(service.clone().handle(stream));
        }
    }

    async fn as_json(&self) -> String {
        let mut json = String::new();
        let watchs = self.watchs.lock().await;
        json.push('{');
        let mut first = true;
        for (name, watch) in watchs.iter() {
            let name = name
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\"", "\\\"");
            if first {
                first = false;
            } else {
                json.push(',');
            }
            json.push('\"');
            json.push_str(&name);
            json.push('\"');
            json.push(':');
            format_json!(
                json,
                "alive_tunnel": watch.alive_tunnel(),
                "busy_tunnel": watch.busy_tunnel(),
                "match_count": watch.match_count(),
                "match_spend_ms": watch.match_spend(),
            );
        }
        json.push('}');
        json
    }
}

struct HyperService {
    watch: Watcher,
    path: String,
}

impl Clone for HyperService {
    fn clone(&self) -> Self {
        Self {
            watch: self.watch.clone(),
            path: self.path.clone(),
        }
    }
}

impl HyperService {
    async fn handle(self, stream: TcpStream) {
        match self.handle_impl(stream).await {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to serve admin http connection: {:#}", e);
            }
        }
    }

    async fn handle_impl(&self, stream: TcpStream) -> Result<()> {
        let io = TokioIo::new(stream);
        http1::Builder::new()
            .serve_connection(io, self)
            .await
            .context("Failed to serve connection")
    }

    async fn hyper_serice(self, req: Request<Incoming>) -> StdResult<Response<String>, Infallible> {
        if req.method() != Method::GET {
            return Ok(Response::builder()
                .status(405)
                .body("Method Not Allowed".to_string())
                .unwrap());
        }
        if req.uri().path() == self.path {
            let json = self.watch.as_json().await;
            Ok(Response::new(json))
        } else {
            Ok(Response::builder()
                .status(404)
                .body("Not Found".to_string())
                .unwrap())
        }
    }
}

impl Service<Request<Incoming>> for HyperService {
    type Response = Response<String>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = StdResult<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let watch = self.clone();
        Box::pin(watch.hyper_serice(req))
    }
}

pub struct WatchOne {
    inner: Arc<WatchOneInner>,
}
struct WatchOneInner {
    alive_tunnel: AtomicI32,
    busy_tunnel: AtomicI32,
    match_spend: Average,
}

impl Clone for WatchOne {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub enum WatchOneGuard {
    Tunnel(WatchOne),
    Relay(WatchOne),
    Match((WatchOne, Instant)),
}

impl Drop for WatchOneGuard {
    fn drop(&mut self) {
        match self {
            WatchOneGuard::Tunnel(watch) => {
                watch
                    .inner
                    .alive_tunnel
                    .fetch_sub(1, std::sync::atomic::Ordering::Release);
            }
            WatchOneGuard::Relay(watch) => {
                watch
                    .inner
                    .busy_tunnel
                    .fetch_sub(1, std::sync::atomic::Ordering::Release);
            }
            WatchOneGuard::Match((watch, start)) => {
                watch.observe_match_spend(start.elapsed());
            }
        }
    }
}

impl Default for WatchOne {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchOne {
    pub fn new() -> Self {
        let inner = WatchOneInner {
            alive_tunnel: AtomicI32::new(0),
            busy_tunnel: AtomicI32::new(0),
            match_spend: Average::new(),
        };
        WatchOne {
            inner: Arc::new(inner),
        }
    }
    pub fn tunnel_guard(&self) -> WatchOneGuard {
        self.inner
            .alive_tunnel
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        WatchOneGuard::Tunnel(self.clone())
    }

    pub fn busy_guard(&self) -> WatchOneGuard {
        self.inner
            .busy_tunnel
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        WatchOneGuard::Relay(self.clone())
    }

    pub fn match_guard(&self) -> WatchOneGuard {
        let start = Instant::now();
        WatchOneGuard::Match((self.clone(), start))
    }

    pub fn observe_match_spend(&self, spend: Duration) {
        let spend = spend.as_millis() as i32;
        self.inner.match_spend.add_value(spend);
    }

    pub fn alive_tunnel(&self) -> i32 {
        self.inner.alive_tunnel.load(Ordering::Acquire)
    }

    pub fn busy_tunnel(&self) -> i32 {
        self.inner.busy_tunnel.load(Ordering::Acquire)
    }

    pub fn match_spend(&self) -> i32 {
        self.inner.match_spend.get_average()
    }

    pub fn match_count(&self) -> i32 {
        self.inner.match_spend.get_count()
    }
}

#[derive(Debug)]
pub struct Average {
    count: AtomicI32,
    average: AtomicI32,
}

impl Default for Average {
    fn default() -> Self {
        Self::new()
    }
}

impl Average {
    pub fn new() -> Self {
        Self {
            count: AtomicI32::new(0),
            average: AtomicI32::new(0),
        }
    }

    pub fn add_value(&self, value: i32) {
        loop {
            let current_count = self.count.load(Ordering::Acquire);
            let current_avg = self.average.load(Ordering::Acquire);
            let new_count = current_count + 1;
            let new_avg_scaled = if current_count == 0 {
                value
            } else {
                current_avg + (value - current_avg) / new_count
            };

            let count_success = self.count.compare_exchange_weak(
                current_count,
                new_count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );

            if count_success.is_ok() {
                let avg_success = self.average.compare_exchange_weak(
                    current_avg,
                    new_avg_scaled,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                );

                if avg_success.is_ok() {
                    break;
                }
            }
        }
    }

    pub fn get_average(&self) -> i32 {
        self.average.load(Ordering::Acquire)
    }

    pub fn get_count(&self) -> i32 {
        self.count.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_average() {
        let average = Average::new();
        average.add_value(10);
        assert_eq!(average.get_average(), 10);
        average.add_value(30);
        assert_eq!(average.get_average(), 20);
        average.add_value(5);
        assert_eq!(average.get_average(), 15);
    }

    #[tokio::test]
    async fn test_watcher() {
        let watcher = Watcher::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let context = Context::default();
        let addr = listener.local_addr().unwrap();
        context.spawn(
            watcher
                .clone()
                .serve_http(context.clone(), listener, "/status".to_string()),
        );
        let watch = watcher.watch("test".to_string()).await;
        let _guard1 = watch.tunnel_guard();
        let _guard2 = watch.busy_guard();
        let guard3 = watch.match_guard();
        drop(guard3);

        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        let mut buffer = [0; 1024];
        loop {
            let n = reader.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            response.push_str(&String::from_utf8_lossy(&buffer[0..n]));
            if response.contains("\r\n\r\n") {
                break;
            }
        }
        assert!(
            response.contains("{\"test\":{\"alive_tunnel\":1,\"busy_tunnel\":1,\"match_count\":1,"),
            "response is not correct:\n{}",
            response,
        );
        drop(writer);
        drop(reader);
        context.cancel();
        context.wait_cancel_and_finish().await;
    }
}
