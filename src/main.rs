mod client;
mod config;
mod encryption;
mod serve;
mod transport;

use anyhow::Result;
use config::ServerConfig;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use encryption::copy_bidirectional;
use encryption::{SessionHalf, client_handshake, server_handshake};
use log::{error, info, warn};
use std::net::SocketAddr;
use std::result::Result::{Err, Ok};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::runtime::Builder;
use transport::{Address, Listener, Stream};

fn main() {
    let cfg = ServerConfig::from_file("server.toml").expect("Failed to load config");
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        println!("hello");
    });
}
