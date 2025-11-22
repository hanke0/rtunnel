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
                Local::now().format("%Y-%m-%dT%H:%M:%S%Z"),
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
