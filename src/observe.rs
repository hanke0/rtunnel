use std::env;
use std::fmt;

use crate::errors::Error;
use crate::errors::Result;

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
        log_level.to_string() + ",quinn=error,quinn_proto=error,rustls=error,tokio_rustls=error"
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
            .map_err(Error::from_any)
    } else {
        builder.try_init().map_err(Error::from_any)
    }
}
