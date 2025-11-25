use std::collections::HashSet;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::Instrument;
use tracing::{debug, error, error_span, info, info_span, trace};

use crate::config::{ClientConfig, ConnectTo};
use crate::errors::{Result, ResultExt as _, whatever};
use crate::transport::{
    Connector, Context, Message, MessageKind, PlainTcpConnector, Stream, TlsConnector, Transport,
    relay_bidirectional, tcp_no_delay,
};

struct ClientOptions<T: Connector> {
    connector: T,
    allows: HashSet<String>,
    idle_connections: usize,
    notify: Sender<i32>,
}

impl<T: Connector> ClientOptions<T> {
    async fn notify_for_new_tunnel(&self, n: i32) {
        match self.notify.send(n).await {
            Ok(_) => {}
            Err(e) => error!("failed to notify for new tunnel: {}", e),
        };
    }
}

type ClientOptionsRef<T> = Arc<ClientOptions<T>>;

/// Starts a tunnel client with the given configuration.
///
/// This function establishes a connection to the tunnel server, performs the
/// handshake, and begins managing tunnel connections. It spawns a background
/// task to maintain the connection pool and handle reconnections.
pub async fn start_client(context: &Context, config: ClientConfig) -> Result<()> {
    match config.connect_to {
        ConnectTo::PlainTcp(cfg) => {
            run_client::<PlainTcpConnector>(
                context,
                config.idle_connections,
                cfg,
                config.allowed_addresses,
            )
            .await
        }
        ConnectTo::TcpWithTls(cfg) => {
            run_client::<TlsConnector>(
                context,
                config.idle_connections,
                cfg,
                config.allowed_addresses,
            )
            .await
        }
    }
}

async fn run_client<T: Connector>(
    context: &Context,
    idle: usize,
    config: T::Config,
    allows: HashSet<String>,
) -> Result<()> {
    let (sender, receiver) = mpsc::channel(idle * 2);
    let connector = T::new(config).await?;
    let options = ClientOptions {
        connector,
        allows,
        idle_connections: idle,
        notify: sender,
    };
    let options = Arc::new(options);
    first_connect(context, options.clone()).await?;
    let connect_to = format!("{}", options.connector);
    context.spawn(
        start_client_sentry(context.children(), options, receiver)
            .instrument(error_span!("client_sentry", connect_to)),
    );
    Ok(())
}

async fn start_client_sentry<T: Connector>(
    context: Context,
    options: ClientOptionsRef<T>,
    receiver: Receiver<i32>,
) {
    keep_client_connections(&context, &options, receiver).await;
    context.cancel_all();
    debug!("client sentry exiting, {}", options.connector);
    context.wait().await;
    debug!("client sentry exited, {}", options.connector);
}

async fn keep_client_connections<T: Connector>(
    context: &Context,
    options: &ClientOptionsRef<T>,
    mut receiver: Receiver<i32>,
) {
    let max_idle = options.idle_connections;
    let mut index: u64 = 0;
    for _ in 0..max_idle {
        if context.has_cancel() {
            info!("client sentry exiting early because of context cancel");
            return;
        }
        index += 1;
        trace!("spawning initial tunnel {}", index);
        context.spawn(
            build_tunnel(context.clone(), options.clone()).instrument(error_span!("tunnel", index)),
        );
    }
    while !context.has_cancel() {
        select! {
            n = receiver.recv() => {
                for _ in 0..n.unwrap_or(0) {
                    index += 1;
                    trace!("spawning new tunnel {}", index);
                    context.spawn(build_tunnel(context.clone(), options.clone()).instrument(error_span!(
                        "tunnel",
                        index
                    )));
                }
            },
            _ = context.wait_cancel() => break,
        };
    }
}

async fn build_tunnel<T: Connector>(context: Context, options: ClientOptionsRef<T>) {
    if context.has_cancel() {
        return;
    }
    match build_tunnel_impl(&context, &options).await {
        Ok(_) => {}
        Err(e) => {
            error!("tunnel relay fail: {:#}", e);
            options.notify_for_new_tunnel(1).await;
        }
    }
}

async fn build_tunnel_impl<T: Connector>(
    context: &Context,
    options: &ClientOptionsRef<T>,
) -> Result<()> {
    let (stream, server_addr) = context.race(options.connector.connect()).await?;
    wait_relay(context, stream, options)
        .instrument(info_span!("relay", server_addr))
        .await
}

async fn first_connect<T: Connector>(
    context: &Context,
    options: ClientOptionsRef<T>,
) -> Result<()> {
    let (stream, id) = options.connector.connect().await?;
    let new_ctx = context.clone();
    context.spawn(async move {
        let options = options;
        match wait_relay(&new_ctx, stream, &options)
            .instrument(info_span!("wait_relay", server_addr = id, first = true))
            .await
        {
            Ok(_) => {}
            Err(e) => {
                error!("tunnel relay fail: {:#}", e);
            }
        }
    });
    Ok(())
}

async fn wait_relay<T: Connector>(
    context: &Context,
    mut stream: T::Stream,
    options: &ClientOptionsRef<T>,
) -> Result<()> {
    info!("connected to server");
    let mut message = Message::default();

    let addr = loop {
        context.race(message.read_from_inplace(&mut stream)).await?;
        match message.get_type() {
            MessageKind::Ping => {
                stream.write_all(message.as_ref()).await?;
                continue;
            }
            MessageKind::Connect => {
                let addr =
                    String::from_utf8(message.get_payload().to_vec()).context("Invalid address")?;
                break addr;
            }
            MessageKind::Require => {
                let n = message.parse_require()?;
                options.notify_for_new_tunnel(n).await;
                continue;
            }
        }
    };
    trace!("tunnel connect message has received: {}", addr);
    options.notify_for_new_tunnel(1).await;
    match handle_relay::<T>(context, stream, options, &addr)
        .instrument(info_span!("connect_local", client_addr = addr))
        .await
    {
        Ok((read, write)) => {
            info!(
                "stream disconnected and has read {} bytes and wrote {}",
                read, write
            );
        }
        Err(e) => {
            if e.is_relay_critical() {
                error!("stream relay critical error:  {:#}", e);
            } else {
                info!("stream relay non-critical error:  {:#}", e);
            }
        }
    };
    Ok(())
}

async fn handle_relay<T: Connector>(
    context: &Context,
    stream: T::Stream,
    options: &ClientOptionsRef<T>,
    addr: &String,
) -> Result<(u64, u64)> {
    if !options.allows.contains(addr) {
        return Err(whatever!("Address not allowed: {}", addr));
    }
    let transport = Transport::parse(addr).context("Invalid address")?;
    match transport {
        Transport::Tcp(addr) => {
            let conn = context
                .race(TcpStream::connect(addr))
                .await
                .context("Failed to connect to local service")?;

            tcp_no_delay(&conn);
            let local_addr = format!("{}-{}", conn.local_addr()?, conn.peer_addr()?);
            debug!("connect to local service: {}", local_addr);
            handle_relay_impl::<T, TcpStream>(stream, conn)
                .instrument(info_span!("handle_relay", local_addr))
                .await
        }
    }
}

async fn handle_relay_impl<T: Connector, S: Stream>(
    remote: T::Stream,
    local: S,
) -> Result<(u64, u64)> {
    debug!("start copy_bidirectional");
    relay_bidirectional(remote, local).await
}
