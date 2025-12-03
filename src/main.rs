use std::process;

use clap::Parser;
use tokio::runtime::Builder;
use tracing::error;

use rtunnel::Context;
use rtunnel::observe;
use rtunnel::{Arguments, run};

fn main() {
    let context = Context::new();
    let options = Arguments::parse();
    observe::setup(options.log_level).unwrap();
    let res = block_on(run(&context, options));
    match res {
        Ok(_) => {}
        Err(e) => {
            error!("process exit with error: {e}");
            process::exit(1);
        }
    }
}

fn block_on<F: Future>(task: F) -> F::Output {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(task)
}
