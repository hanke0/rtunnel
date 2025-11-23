use std::collections::HashSet;
use std::sync::Arc;

use log::{debug, error, info, trace};
use tokio::io::AsyncWriteExt;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::config::ClientConfig;
use crate::config::build_connector;
use crate::errors::{Result, ResultExt as _, whatever};
use crate::transport::{Connector, Context, Message, Stream, copy_bidirectional};

struct ClientOptions {
    connector: Connector,
    allows: HashSet<String>,
    idle_connections: i32,
    notify: Sender<()>,
}

impl ClientOptions {
    async fn notify_for_new_tunnel(&self) {
        match self.notify.send(()).await {
            Ok(_) => {}
            Err(e) => error!("failed to notify for new tunnel: {}", e),
        };
    }
}

type ClientOptionsRef = Arc<ClientOptions>;

/// Starts a tunnel client with the given configuration.
///
/// This function establishes a connection to the tunnel server, performs the
/// handshake, and begins managing tunnel connections. It spawns a background
/// task to maintain the connection pool and handle reconnections.
pub async fn start_client(context: &Context, cfg: &ClientConfig) -> Result<()> {
    let connector = build_connector(cfg.connect_to.clone())?;
    let (sender, receiver) = mpsc::channel(cfg.idle_connections as usize);
    let options = Arc::new(ClientOptions {
        connector,
        allows: cfg.allowed_addresses.clone(),
        idle_connections: cfg.idle_connections,
        notify: sender,
    });
    first_connect(context, options.clone()).await?;
    context.spawn(start_client_sentry(context.children(), options, receiver));
    Ok(())
}

async fn start_client_sentry(context: Context, options: ClientOptionsRef, receiver: Receiver<()>) {
    keep_client_connections(&context, &options, receiver).await;
    context.cancel_all();
    debug!("client sentry exiting, {}", options.connector);
    context.wait().await;
    debug!("client sentry exited, {}", options.connector);
}

async fn keep_client_connections(
    context: &Context,
    options: &ClientOptionsRef,
    mut receiver: Receiver<()>,
) {
    let max_idle = options.idle_connections;
    for _ in 0..max_idle {
        if context.has_cancel() {
            return;
        }
        context.spawn(build_tunnel(context.clone(), options.clone()));
    }
    while !context.has_cancel() {
        select! {
            _ = receiver.recv() => {
                context.spawn(build_tunnel(context.clone(), options.clone()));
            },
            _ = context.wait_cancel() => break,
        };
    }
}

async fn build_tunnel(context: Context, options: ClientOptionsRef) {
    if context.has_cancel() {
        return;
    }
    match build_tunnel_impl(&context, &options).await {
        Ok(_) => {}
        Err(e) => {
            error!("tunnel relay fail: {:#}", e);
            options.notify_for_new_tunnel().await;
        }
    }
}

async fn build_tunnel_impl(context: &Context, options: &ClientOptionsRef) -> Result<()> {
    let stream = options.connector.connect(context).await?;
    wait_relay(context, stream, options).await
}

async fn first_connect(context: &Context, options: ClientOptionsRef) -> Result<()> {
    let stream = options.connector.connect(context).await?;
    let new_ctx = context.clone();
    context.spawn(async move {
        let options = options;
        match wait_relay(&new_ctx, stream, &options).await {
            Ok(_) => {}
            Err(e) => {
                error!("tunnel relay fail: {:#}", e);
            }
        }
    });
    Ok(())
}

async fn wait_relay(
    context: &Context,
    mut stream: Stream,
    options: &ClientOptionsRef,
) -> Result<()> {
    debug!("tunnel established, wait connect message: {}", stream);
    let mut message = Message::default();
    let addr = message
        .wait_connect_message(context, &mut stream)
        .await
        .context("Failed to wait connect message")?;
    let debug = format!("{}->{}", stream, addr);
    trace!("tunnel connect message has received: {}", debug);
    options.notify_for_new_tunnel().await;
    match handle_relay(context, stream, options, &addr, &mut message).await {
        Ok((read, write)) => {
            info!(
                "stream {} disconnected and has read {} bytes and wrote {}",
                debug, read, write
            );
        }
        Err(e) => {
            if e.is_relay_critical() {
                error!("stream {} relay critical error:  {:#}", debug, e);
            } else {
                info!("stream {} relay non-critical error:  {:#}", debug, e);
            }
        }
    };
    Ok(())
}

async fn handle_relay(
    context: &Context,
    mut stream: Stream,
    options: &ClientOptionsRef,
    addr: &String,
    message: &mut Message,
) -> Result<(u64, u64)> {
    trace!("tunnel connect message has read: {}", addr);
    if !options.allows.contains(addr) {
        return Err(whatever!("Address not allowed: {}", addr));
    }
    let conn = Connector::parse_address(addr)?
        .connect(context)
        .await
        .context("Failed to connect to local service")?;
    message.connect_inplace("");
    stream.write_all(message.as_ref()).await?;
    debug!("tunnel relay started: {}->{}", &stream, addr);
    copy_bidirectional(stream, conn).await
}
