use std::process;

use clap::Parser;
use tokio::runtime::Builder;

use rtunnel::Context;
use rtunnel::setup;
use rtunnel::{Arguments, run};

fn main() {
    let context = Context::new();
    let options = Arguments::parse();
    setup(options.log_level, false);
    let res = block_on(run(&context, options));
    process::exit(res);
}

fn block_on<F: Future>(task: F) -> F::Output {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(task)
}
