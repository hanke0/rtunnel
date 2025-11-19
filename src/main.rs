use std::io::Write;
use std::process;

use chrono::Local;
use clap::Parser;
use tokio::runtime::Builder;

use rtunnel::Context;
use rtunnel::{Arguments, run};

fn main() {
    let controller = Context::new();
    let options = Arguments::parse();
    env_logger::Builder::new()
        .filter_level(options.log_level)
        .format_indent(Some(4))
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
        .init();

    let res = block_on(run(&controller, options));
    process::exit(res);
}

fn block_on<F: Future>(task: F) -> F::Output {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(task)
}
