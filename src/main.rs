mod client;
mod config;
mod encryption;
mod server;
mod transport;

use std::process;
use std::string::String;
use std::time::Duration;
use tokio::time::sleep;

use clap::{Parser, Subcommand};
use config::{ClientConfig, ServerConfig};
use encryption::KeyPair;
use env_logger;
use log::{debug, error, info};
use tokio::runtime::Builder;
use tokio::signal::unix::SignalKind;
use tokio::{select, signal};
use transport::Controller;

fn main() {
    let options = Cli::parse();
    env_logger::Builder::new()
        .filter_level(options.log_level)
        .format_indent(Some(4))
        .init();

    match options.command {
        Commands::GenerateKey {} => {
            let pair = KeyPair::random();
            pair.print();
        }
        Commands::Client { config } => {
            info!("starting client, loading config from {}", config);
            let configs = ClientConfig::from_file(&config).expect("Failed to load config");
            block_on(start_client(configs));
        }
        Commands::Server { config } => {
            info!("starting server, loading config from {}", config);
            let configs = ServerConfig::from_file(&config).expect("Failed to load config");
            block_on(start_server(configs));
        }
    }
}

fn block_on<F: Future>(task: F) {
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(task);
}

async fn start_client(configs: Vec<ClientConfig>) {
    let controller = Controller::default();
    debug!("starting {} clients", configs.len());
    for cfg in configs.iter() {
        let err = client::start_client(&controller, cfg).await;
        if err.is_ok() {
            info!("connected to {}", cfg.server_address);
            continue;
        }
        error!(
            "connect to {} failed, exiting: {:#}",
            cfg.server_address,
            err.unwrap_err()
        );
        graceful_exit(&controller, 1, "client").await
    }
    info!("all clients started, client is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = controller.wait_cancel() => {}
    }
    info!("client is shutting down");
    graceful_exit(&controller, 0, "client").await
}

async fn start_server(configs: Vec<ServerConfig>) {
    let controller = Controller::default();
    debug!("starting {} server", configs.len());
    for cfg in configs.iter() {
        let err = server::start_server(&controller, cfg).await;
        if err.is_ok() {
            continue;
        }
        error!(
            "start server {} failed, exiting: {:#}",
            cfg.listen,
            err.unwrap_err()
        );
        graceful_exit(&controller, 1, "server").await;
    }
    info!("all service started, server is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = controller.wait_cancel() => {}
    }
    info!("server is shutting down");
    graceful_exit(&controller, 0, "server").await;
}

async fn wait_exit_signal() {
    let mut sigint = signal::unix::signal(SignalKind::terminate()).unwrap();
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

async fn graceful_exit(controller: &Controller, code: i32, side: &str) -> ! {
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
    process::exit(code);
}

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "rtunnel")]
#[command(about = "A simple and reliable tunnel", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(
        short = 'l',
        long = "log-level",
        help = "log level",
        default_value = "info"
    )]
    log_level: log::LevelFilter,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = false)]
    GenerateKey {},
    #[command(arg_required_else_help = false)]
    Client {
        #[arg(
            short = 'c',
            long = "config",
            help = "config file path",
            default_value = "rtunnel.toml"
        )]
        config: String,
    },
    #[command(arg_required_else_help = false)]
    Server {
        #[arg(
            short = 'c',
            long = "config",
            help = "config file path",
            default_value = "rtunnel.toml"
        )]
        config: String,
    },
}
