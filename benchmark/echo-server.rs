use std::env;
use std::error::Error;

mod common;

use crate::common::run_echo_server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    run_echo_server(env::args().nth(1).unwrap().as_ref(), true).await
}
