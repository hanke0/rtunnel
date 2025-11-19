use std::string::String;
use std::time::Duration;

use clap::{Parser, Subcommand};
use log::{debug, error, info};
use tokio::select;
use tokio::time::sleep;

pub mod client;
pub mod config;
pub mod encryption;
pub mod errors;
pub mod server;
pub mod transport;

pub use crate::config::{ClientConfig, ServerConfig};
use crate::encryption::KeyPair;
pub use crate::encryption::generate_random_bytes;
pub use crate::transport::Context;

/// Runs the rtunnel application based on the provided CLI options.
///
/// This function handles the main command-line interface and dispatches to
/// the appropriate handler based on the selected command.
pub async fn run(controller: &Context, args: Arguments) -> i32 {
    match args.command {
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

/// Runs the client mode of rtunnel.
///
/// This function starts one or more client connections based on the provided
/// configurations. Each client connects to a tunnel server and manages
/// connections for relaying traffic.
pub async fn run_client(controller: &Context, configs: Vec<ClientConfig>) -> i32 {
    debug!("starting {} clients", configs.len());
    for cfg in configs.iter() {
        let err = client::start_client(controller, cfg).await;
        match err {
            Ok(_) => continue,
            Err(e) => {
                error!("connect to {} failed, exiting: {:#}", cfg.server_address, e);
                graceful_exit(controller, "client").await;
                return 1;
            }
        }
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

/// Runs the server mode of rtunnel.
///
/// This function starts one or more server instances based on the provided
/// configurations. Each server listens for tunnel connections and manages
/// services that forward traffic to backend services.
///
/// # Arguments
///
/// * `controller` - The controller for managing async tasks and cancellation
/// * `configs` - A vector of server configurations to start
///
/// # Returns
///
/// Returns an exit code: 0 for success, 1 for failure
pub async fn run_server(controller: &Context, configs: Vec<ServerConfig>) -> i32 {
    debug!("starting {} server", configs.len());
    for cfg in configs.iter() {
        let err = server::start_server(controller, cfg).await;
        match err {
            Ok(_) => continue,
            Err(e) => {
                error!("start server {} failed, exiting: {:#}", cfg.listen, e);
                graceful_exit(controller, "server").await;
                return 1;
            }
        }
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
    let sigint_msg = "received ctrl-c signal";
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        select! {
            _ = sigint.recv() => {
                info!("{sigint_msg}");
            }
            _ = sigterm.recv() => {
                info!("received sigterm signal");
            }
        };
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};
        let mut sigint = ctrl_c().unwrap();
        let mut sigclose = ctrl_close().unwrap();
        let mut sigbreak = ctrl_break().unwrap();
        let mut sigshutdown = ctrl_shutdown().unwrap();
        select! {
            _ = sigint.recv() => {
                info!("{sigint_msg}");
            }
            _ = sigclose.recv() => {
                info!("received ctrl-close signal");
            }
            _ = sigbreak.recv() => {
                info!("received ctrl-break signal");
            }
            _ = sigshutdown.recv() => {
                info!("received ctrl-shutdown signal");
            }
        }
    }
}

async fn graceful_exit(controller: &Context, side: &str) {
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
    info!("{side} has shutdown");
}

/// Command-line interface arguments structure for rtunnel.
///
/// This struct represents the top-level CLI arguments and commands.
/// It is used to parse and handle command-line input.
#[derive(Debug, Parser)] // requires `derive` feature
#[command(
    name = "rtunnel",
    version,
    about = "A lightweight tunnel tool.",
    long_about = "A lightweight tunneling tool, written in Rust, for exposing local servers behind NATs and firewalls to the public internet."
)]
pub struct Arguments {
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

/// Available commands for the rtunnel CLI.
///
/// This enum represents all the subcommands that can be executed by rtunnel.
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
