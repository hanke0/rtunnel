use std::collections::HashSet;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info, trace};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::config::ClientConfig;
use crate::encryption::client_handshake;
use crate::encryption::copy_encrypted_bidirectional;
use crate::encryption::{ReadSession, WriteSession};
use crate::encryption::{decode_signing_key, decode_verifying_key};
use crate::errors::{Result, ResultExt as _, whatever};
use crate::transport::{Address, Context};

struct ClientOptions {
    address: Address,
    verifier: VerifyingKey,
    signer: SigningKey,
    allows: HashSet<Address>,
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
    let verifier = decode_verifying_key(&cfg.server_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let (sender, receiver) = mpsc::channel(cfg.idle_connections as usize);
    let options = Arc::new(ClientOptions {
        address: cfg.server_address,
        verifier,
        signer,
        allows: cfg.allowed_addresses.clone(),
        idle_connections: cfg.idle_connections,
        notify: sender,
    });
    first_connect(context.clone(), options.clone()).await?;
    context.spawn(start_client_sentry(context.children(), options, receiver));
    Ok(())
}

async fn start_client_sentry(context: Context, options: ClientOptionsRef, receiver: Receiver<()>) {
    keep_client_connections(&context, &options, receiver).await;
    context.cancel_all();
    debug!("client sentry exiting, {}", options.address);
    context.wait().await;
    debug!("client sentry exited, {}", options.address);
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
    let (read_half, write_half) = connect_to_server(context, options).await?;
    wait_relay(context, read_half, write_half, options).await
}

async fn first_connect(context: Context, options: ClientOptionsRef) -> Result<()> {
    let (r, w) = connect_to_server(&context, &options).await?;
    let c = context.clone();
    context.spawn(async move {
        let context = c;
        let options = options;
        match wait_relay(&context, r, w, &options).await {
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
    mut read_half: ReadSession,
    mut write_half: WriteSession,
    options: &ClientOptionsRef,
) -> Result<()> {
    let addr: Address = read_half
        .wait_connect_message(context, &mut write_half)
        .await
        .with_context(|| format!("Failed to wait connect message: {}", read_half))?;
    let debug = format!("{}->{}", read_half, addr);
    options.notify_for_new_tunnel().await;
    match handle_relay(context, read_half, write_half, options, &addr).await {
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

async fn connect_to_server(
    context: &Context,
    options: &ClientOptionsRef,
) -> Result<(ReadSession, WriteSession)> {
    let conn = options
        .address
        .connect_to(context)
        .await
        .context("Failed to connect to tunnel server")?;
    debug!("connected to server: {}", conn);
    let (read_half, write_half) = client_handshake(
        context,
        conn.reader,
        conn.writer,
        &options.signer,
        &options.verifier,
    )
    .await?;
    debug!("handshake success, tunnel established: {}", read_half);
    Ok((read_half, write_half))
}

async fn handle_relay(
    context: &Context,
    read_half: ReadSession,
    mut write_half: WriteSession,
    options: &ClientOptionsRef,
    addr: &Address,
) -> Result<(usize, usize)> {
    trace!("tunnel connect message has read: {}", addr);
    if !options.allows.contains(addr) {
        return Err(whatever!("Address not allowed: {}", addr));
    }
    let conn = addr
        .connect_to(context)
        .await
        .context("Failed to connect to local service")?;
    write_half.write_connect_message(context, addr).await?;
    debug!("tunnel relay started: {}->{}", &read_half, addr);
    copy_encrypted_bidirectional(context, read_half, write_half, conn.reader, conn.writer).await
}
