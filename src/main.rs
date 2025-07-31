mod client;
mod config;
mod encryption;
mod serve;
mod transport;

use config::ServerConfig;
use tokio::runtime::Builder;

fn main() {
    let _cfg = ServerConfig::from_file("server.toml").expect("Failed to load config");
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        println!("hello");
    });
}
