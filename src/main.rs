mod config;
mod transport;
mod encryption;
use config;
use std::process::exit;
use tokio::runtime::Builder;

fn main() {
    let cfg = config::from_file::<config::ServerConfig>("server.toml");
    if cfg.is_err() {
        eprintln!("Failed to load config: {}", cfg.err().unwrap());
        exit(1);
    }
    let _cfg = cfg.unwrap();
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        println!("hello");
    });
}
