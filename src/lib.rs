use std::string::String;
use std::time::Duration;

use clap::{Parser, Subcommand};
use log::{debug, info};
use tokio::signal::unix::SignalKind;
use tokio::time::sleep;
use tokio::{select, signal};

pub mod client;
pub mod config;
pub mod encryption;
pub mod errors;
pub mod server;
pub mod transport;

pub use crate::config::{ClientConfig, ServerConfig};
use crate::encryption::KeyPair;
pub use crate::encryption::generate_random_bytes;
pub use crate::transport::Controller;

pub async fn run(controller: &Controller, options: Cli) -> i32 {
    match options.command {
        Commands::GenerateKey {} => {
            let pair = KeyPair::random();
            pair.print();
            0
        }
        Commands::ExampleConfig {} => {
            println!("{}", build_example_config());
            0
        }
        Commands::Client { config } => {
            info!("starting client, loading config from {}", config);
            let configs = ClientConfig::from_file(&config).expect("Failed to load config");
            run_client(controller, configs).await
        }
        Commands::Server { config } => {
            info!("starting server, loading config from {}", config);
            let configs = ServerConfig::from_file(&config).expect("Failed to load config");
            run_server(controller, configs).await
        }
    }
}

pub async fn run_client(controller: &Controller, configs: Vec<ClientConfig>) -> i32 {
    debug!("starting {} clients", configs.len());
    for cfg in configs.iter() {
        let err = client::start_client(controller, cfg).await;
        if err.is_ok() {
            info!("connected to {}", cfg.server_address);
            continue;
        }
        format_err!(
            "connect to {} failed, exiting: {:#}",
            cfg.server_address,
            err.unwrap_err()
        );
        graceful_exit(controller, "client").await;
        return 1;
    }
    info!("all clients started, client is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = controller.wait_cancel() => {}
    }
    info!("client is shutting down");
    graceful_exit(controller, "client").await;
    0
}

pub async fn run_server(controller: &Controller, configs: Vec<ServerConfig>) -> i32 {
    debug!("starting {} server", configs.len());
    for cfg in configs.iter() {
        let err = server::start_server(controller, cfg).await;
        if err.is_ok() {
            continue;
        }
        format_err!(
            "start server {} failed, exiting: {:#}",
            cfg.listen,
            err.unwrap_err()
        );
        graceful_exit(controller, "server").await;
        return 1;
    }
    info!("all service started, server is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = controller.wait_cancel() => {}
    }
    info!("server is shutting down");
    graceful_exit(controller, "server").await;
    0
}

async fn wait_exit_signal() {
    let mut sigint = signal::unix::signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal::unix::signal(SignalKind::terminate()).unwrap();
    select! {
        _ = sigint.recv() => {
            info!("received ctrl-c signal");
        }
        _ = sigterm.recv() => {
            info!("received sigterm signal");
        }
    };
}

async fn graceful_exit(controller: &Controller, side: &str) {
    controller.cancel_all();
    loop {
        select! {
            _ = controller.wait() => {
                break;
            }
            _ = sleep(Duration::from_millis(1000)) => {
                debug!("{side} is still shutting down, task count {}", controller.task_count());
            }
        }
    }
}

#[derive(Debug, Parser)] // requires `derive` feature
#[command(
    name = "rtunnel",
    version,
    about = "A lightweight tunnel tool.",
    long_about = "A lightweight tunneling tool, written in Rust, for exposing local servers behind NATs and firewalls to the public internet."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(
        short = 'l',
        long = "log-level",
        help = "set log level (trace, debug, info, warn, error, off)",
        default_value = "info",
        global = true
    )]
    #[clap(value_enum)]
    pub log_level: log::LevelFilter,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(
        about = "generate public and private key pair",
        arg_required_else_help = false
    )]
    GenerateKey {},
    #[command(
        about = "Generate example config to stdout",
        arg_required_else_help = false
    )]
    ExampleConfig {},
    #[command(
        about = "Run the client to route traffic between the local machine and the tunnel",
        arg_required_else_help = false
    )]
    Client {
        #[arg(
            short = 'c',
            long = "config",
            help = "config file path",
            default_value = "rtunnel.toml",
            value_hint = clap::ValueHint::FilePath
        )]
        config: String,
    },
    #[command(
        about = "Run the server to route traffic between the tunnel and the public internet",
        arg_required_else_help = false
    )]
    Server {
        #[arg(
            short = 'c',
            long = "config",
            help = "config file path",
            default_value = "rtunnel.toml",
            value_hint = clap::ValueHint::FilePath
        )]
        config: String,
    },
}

fn build_example_config() -> String {
    let client_pair = KeyPair::random();
    let server_pair = KeyPair::random();
    let server_private = server_pair.private_key();
    let server_public = server_pair.public_key();
    let client_private = client_pair.private_key();
    let client_public = client_pair.public_key();

    format!(
        "# Example config for server
[[servers]]
private_key = \"{server_private}\"
public_key = \"{server_public}\"
client_public_key = \"{client_public}\"
listen = \"tcp://127.0.0.1:7000\"

services = [
    {{ bind_to = \"tcp://0.0.0.0:8001\", connect_to = \"tcp://127.0.0.1:80\" }},
]

# Example config for client
[[clients]]
private_key = \"{client_private}\"
public_key = \"{client_public}\"
server_public_key = \"{server_public}\"

server_address = \"tcp://127.0.0.1:7000\"

allowed_addresses = [
    \"tcp://127.0.0.1:80\",
]
    "
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config() {
        let cfg = build_example_config();
        assert!(!cfg.is_empty());
        ServerConfig::from_string(&cfg).unwrap();
        ClientConfig::from_string(&cfg).unwrap();
    }
}
