use std::io::Write;

use chrono::Local;
use log::LevelFilter;

pub fn setup_logger(log_level: log::LevelFilter, testing: bool) {
    let r = env_logger::Builder::new()
        .filter_level(log_level)
        .format_indent(Some(4))
        .filter_module("rustls", LevelFilter::Off)
        .is_test(testing)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] [{}:{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f%Z"),
                record.level(),
                record.file().unwrap_or("-"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .try_init();
    if !testing {
        r.unwrap();
    }
}

#[macro_export]
macro_rules! debug_spend {
    ($s: block, $fmt:expr, $($arg:tt)*) => {{
        #[cfg(any(feature = "debug", test))]
        let start = std::time::Instant::now();
        let result = $s;
        #[cfg(any(feature = "debug", test))]
        log::trace!("{}, spend {:?}", format_args!($fmt, $($arg)*), start.elapsed());
        result
    }};
}

pub use debug_spend;
