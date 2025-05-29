mod config;
mod encryption;
mod transport;
use std::process::exit;
use tokio::runtime::Builder;

fn main() {
    let cfg = config::from_file::<config::ServerConfig>("server.toml");
    if cfg.is_err() {
        eprintln!("Failed to load config: {:?}", cfg.unwrap_err());
        exit(1);
    }
    let _cfg = cfg.unwrap();
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        println!("hello");
    });
}
