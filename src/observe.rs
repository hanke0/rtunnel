use crate::errors::Error;
use crate::errors::Result;

pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn to_level_filter(self) -> tracing_subscriber::filter::LevelFilter {
        match self {
            Level::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
            Level::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
            Level::Info => tracing_subscriber::filter::LevelFilter::INFO,
            Level::Warn => tracing_subscriber::filter::LevelFilter::WARN,
            Level::Error => tracing_subscriber::filter::LevelFilter::ERROR,
        }
    }
}

pub fn setup(log_level: Level) -> Result<()> {
    let r = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(log_level.to_level_filter())
        .try_init()
        .map_err(Error::from_any);
    Ok(r?)
}

pub fn setup_testing() {
    setup(Level::Trace);
}
