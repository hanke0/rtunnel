use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicI32, AtomicU32};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::errors::Result;
use crate::errors::ResultExt;

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
    watchs: Mutex<BTreeMap<String, WatchOne>>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Watcher {
    pub fn new() -> Self {
        Self {
            watchs: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn watch(&self, name: String) -> WatchOne {
        let watch = WatchOne::new();
        self.watchs.lock().await.insert(name, watch.clone());
        watch
    }

    pub async fn as_json(&self) -> String {
        let mut json = String::new();
        let watchs = self.watchs.lock().await;
        json.push('{');
        let mut first = true;
        for (name, watch) in watchs.iter() {
            let alive_tunnel = watch.alive_tunnel();
            let busy_tunnel = watch.busy_tunnel();
            let name = name
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\"", "\\\"");
            if first {
                first = false;
            } else {
                json.push(',');
            }
            json = json
                + &format!(
                    "\"{name}\": {{\"alive_tunnel\":{alive_tunnel},\"busy_tunnel\":{busy_tunnel}}}"
                );
        }
        json.push('}');
        json
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
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
            }
            WatchOneGuard::Relay(watch) => {
                watch
                    .inner
                    .busy_tunnel
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
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
        let spend = spend.as_millis() as u32;
        self.inner.match_spend.add_value(spend);
    }

    pub fn alive_tunnel(&self) -> i32 {
        self.inner.alive_tunnel.load(Ordering::Acquire)
    }

    pub fn busy_tunnel(&self) -> i32 {
        self.inner.busy_tunnel.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct Average {
    count: AtomicU32,
    average: AtomicU32,
}

impl Default for Average {
    fn default() -> Self {
        Self::new()
    }
}

impl Average {
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            average: AtomicU32::new(0),
        }
    }

    pub fn add_value(&self, value: u32) {
        loop {
            let current_count = self.count.load(std::sync::atomic::Ordering::Acquire);
            let current_avg = self.average.load(std::sync::atomic::Ordering::Acquire);
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

    pub fn get_average(&self) -> u32 {
        self.average.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn get_count(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }
}
