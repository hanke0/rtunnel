use std::process;

use clap::Parser;
use tokio::runtime::Builder;

use rtunnel::Controller;
use rtunnel::{Cli, run};

fn main() {
    let controller = Controller::new();
    let options = Cli::parse();
    env_logger::Builder::new()
        .filter_level(options.log_level)
        .format_indent(Some(4))
        .init();

    let res = block_on(run(&controller, options));
    process::exit(res);
}

fn block_on<F: Future>(task: F) -> F::Output {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(task)
}
