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
    setup_impl(log_level, false)
}

pub fn setup_testing() {
    let _ = setup_impl(Level::Trace, true);
}

fn setup_impl(log_level: Level, is_testing: bool) -> Result<()> {
    let builder = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(log_level.to_level_filter());
    if is_testing {
        builder
            .with_test_writer()
            .try_init()
            .map_err(Error::from_any)
    } else {
        builder.try_init().map_err(Error::from_any)
    }
}
