mod config;
use std::process::exit;
use config::{ServerConfig, from_file};
use tokio::runtime::Builder;

fn main() {
    let cfg = from_file::<ServerConfig>("server.toml");
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
