use std::fs;
use std::path::PathBuf;
use std::string::String;
use std::sync::Once;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::select;
use tokio::time::sleep;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tracing::{debug, error, info};

pub mod client;
pub mod config;
pub mod errors;
pub mod observe;
pub mod server;
pub mod transport;

pub use crate::config::{AdminConfig, ClientConfig, Config, ServerConfig};
pub use crate::transport::Context;

use crate::errors::{Result, ResultExt};
use crate::observe::Watcher;

/// Runs the rtunnel application based on the provided CLI options.
///
/// This function handles the main command-line interface and dispatches to
/// the appropriate handler based on the selected command.
pub async fn run(context: &Context, args: Arguments) -> Result<()> {
    match args.command {
        Commands::ExampleConfig { subject, r#type } => {
            match r#type {
                ExampleConfigType::TlsTcp => {
                    println!("{}", config::build_tls_example(&subject));
                }
                ExampleConfigType::PlainTcp => {
                    println!("{}", config::build_tcp_example());
                }
                ExampleConfigType::Quic => {
                    println!("{}", config::build_quic_example(&subject));
                }
            }
            Ok(())
        }
        Commands::SelfSignedCert { .. } => {
            write_self_signed_cert(args.command);
            Ok(())
        }
        Commands::Client { config } => {
            info!("starting client, loading config from {}", config);
            let config = Config::from_file(&config).expect("Failed to load config");
            run_client(context, config).await
        }
        Commands::Server { config } => {
            info!("starting server, loading config from {}", config);
            let config = Config::from_file(&config).expect("Failed to load config");
            run_server(context, config).await
        }
    }
}

/// Runs the client mode of rtunnel.
///
/// This function starts one or more client connections based on the provided
/// configurations. Each client connects to a tunnel server and manages
/// connections for relaying traffic.
pub async fn run_client(context: &Context, config: Config) -> Result<()> {
    warmup_aws_lc_rs();
    let watch = build_watch(context, config.admin).await?;
    debug!("starting {} clients", config.clients.len());
    for cfg in config.clients.iter() {
        let err = client::start_client(context, cfg.clone(), &watch).await;
        match err {
            Ok(_) => continue,
            Err(e) => {
                error!("connect to {} failed, exiting: {:#}", cfg.connect_to, e);
                graceful_exit(context, "client").await;
                return Err(e);
            }
        }
    }
    info!("all clients started, client is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = context.wait_finish() => {}
    }
    info!("client is shutting down");
    graceful_exit(context, "client").await;
    Ok(())
}

/// Runs the server mode of rtunnel.
///
/// This function starts one or more server instances based on the provided
/// configurations. Each server listens for tunnel connections and manages
/// services that forward traffic to backend services.
pub async fn run_server(context: &Context, config: Config) -> Result<()> {
    warmup_aws_lc_rs();
    let watch = build_watch(context, config.admin).await?;
    debug!("starting {} server", config.servers.len());
    for cfg in config.servers.iter() {
        let err = server::start_server(context, cfg.clone(), &watch).await;
        match err {
            Ok(_) => continue,
            Err(e) => {
                error!("start server {} failed, exiting: {:#}", cfg.listen_to, e);
                graceful_exit(context, "server").await;
                return Err(e);
            }
        }
    }
    info!("all service started, server is ready");
    select! {
            _ = wait_exit_signal() => {},
            _ = context.wait_finish() => {}
    }
    info!("server is shutting down");
    graceful_exit(context, "server").await;
    Ok(())
}

async fn build_watch(context: &Context, config: Option<AdminConfig>) -> Result<Watcher> {
    let watch = Watcher::new();
    if let Some(config) = config {
        let listener = TcpListener::bind(config.listen_to)
            .await
            .context("bind admin listener failed")?;
        let watch = watch.clone();
        tokio::spawn(watch.serve_http(context.clone(), listener, config.get_http_path()));
    }
    Ok(watch)
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

async fn graceful_exit(context: &Context, side: &str) {
    context.cancel_all();
    loop {
        select! {
            _ = context.wait_cancel_and_finish() => {
                break;
            }
            _ = sleep(Duration::from_millis(1000)) => {
                debug!("{side} is still shutting down, task count {}", context.task_count());
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
    pub log_level: observe::Level,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum ExampleConfigType {
    TlsTcp,
    PlainTcp,
    Quic,
}

/// Available commands for the rtunnel CLI.
///
/// This enum represents all the subcommands that can be executed by rtunnel.
#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(
        about = "Generate example config to stdout",
        arg_required_else_help = false
    )]
    ExampleConfig {
        #[arg(help = "subject name for the certificate")]
        subject: String,
        #[arg(
            short = 't',
            long = "type",
            help = "transport type of config",
            default_value = "tls-tcp"
        )]
        #[clap(value_enum)]
        r#type: ExampleConfigType,
    },
    SelfSignedCert {
        #[arg(help = "subject name for the certificate")]
        subject: String,
        #[arg(
            short = 'o',
            long = "output",
            default_value = ".",
            help = "output directory for the certificate"
        )]
        output: PathBuf,
    },
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

fn warmup_aws_lc_rs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let provider = aws_lc_rs::default_provider();
        provider.secure_random.fill(&mut [0u8]).unwrap();
        provider.clone().install_default().unwrap();
    });
}

fn write_self_signed_cert(opt: Commands) {
    match opt {
        Commands::SelfSignedCert { subject, output } => {
            let cert = config::SelfSignedCert::new(&subject);
            fs::write(output.join("server.crt"), cert.server_cert.clone())
                .expect("Failed to write server cert");
            fs::write(output.join("server.key"), cert.server_key)
                .expect("Failed to write server key");
            fs::write(output.join("server_ca.crt"), cert.client_cert.clone())
                .expect("Failed to write server ca cert");
            fs::write(output.join("client.crt"), cert.client_cert)
                .expect("Failed to write client cert");
            fs::write(output.join("client.key"), cert.client_key)
                .expect("Failed to write client key");
            fs::write(output.join("client_ca.crt"), cert.server_cert)
                .expect("Failed to write client ca cert");
        }
        _ => unreachable!(),
    }
}
