use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info, trace};
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::config::ClientConfig;
use crate::encryption::client_handshake;
use crate::encryption::copy_encrypted_bidirectional;
use crate::encryption::{ReadSession, WriteSession};
use crate::encryption::{decode_signing_key, decode_verifying_key};
use crate::errors::{self, Result, ResultExt as _, is_relay_critical_error};
use crate::transport::{Address, Context};

/// Event notification types for client connection management.
///
/// This enum represents different events that can occur during the lifecycle
/// of client connections, used for tracking connection state and statistics.
#[derive(Clone, Copy)]
pub enum NotifyEvent {
    Shutdown,
    RelayStart,
    RelayFinish,
}

impl fmt::Display for NotifyEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotifyEvent::Shutdown => write!(f, "Shutdown"),
            NotifyEvent::RelayStart => write!(f, "RelayStart"),
            NotifyEvent::RelayFinish => write!(f, "RelayFinish"),
        }
    }
}

struct ClientOptions {
    address: Address,
    verifier: VerifyingKey,
    signer: SigningKey,
    allows: HashSet<Address>,
    max_connections: i32,
    idle_connections: i32,
}

type ClientOptionsRef = Arc<ClientOptions>;

type Sender = UnboundedSender<NotifyEvent>;
type Receiver = UnboundedReceiver<NotifyEvent>;

struct StreamGuarder {
    sender: Sender,
}

impl Clone for StreamGuarder {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl StreamGuarder {
    fn new(sender: Sender) -> Self {
        Self { sender }
    }

    fn relay_guard(&self) -> StreamGuard {
        self.sender.send(NotifyEvent::RelayStart).unwrap();
        StreamGuard {
            sender: self.sender.clone(),
            event: NotifyEvent::RelayFinish,
        }
    }

    fn stream_guard(&self) -> StreamGuard {
        StreamGuard {
            sender: self.sender.clone(),
            event: NotifyEvent::Shutdown,
        }
    }
}

struct StreamGuard {
    sender: Sender,
    event: NotifyEvent,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        match self.sender.send(self.event) {
            Ok(_) => {}
            Err(e) => {
                panic!("send event {} error: {:#}", self.event, e);
            }
        };
    }
}

/// Starts a tunnel client with the given configuration.
///
/// This function establishes a connection to the tunnel server, performs the
/// handshake, and begins managing tunnel connections. It spawns a background
/// task to maintain the connection pool and handle reconnections.
///
/// # Arguments
///
/// * `controller` - The controller for managing async tasks and cancellation
/// * `cfg` - The client configuration
///
/// # Returns
///
/// Returns `Ok(())` if the client starts successfully.
///
/// # Errors
///
/// Returns an error if the configuration is invalid, the connection fails,
/// or the handshake cannot be completed.
pub async fn start_client(controller: &Context, cfg: &ClientConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.server_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let options = Arc::new(ClientOptions {
        address: cfg.server_address,
        verifier,
        signer,
        allows: cfg.allowed_addresses.clone(),
        max_connections: cfg.max_connections,
        idle_connections: cfg.idle_connections,
    });

    let _ = connect_to_server(controller, &options).await?;

    controller.spawn(start_client_sentry(controller.children(), options));
    Ok(())
}

async fn start_client_sentry(controller: Context, options: ClientOptionsRef) {
    let (sender, mut receiver) = unbounded_channel();
    let guard = StreamGuarder::new(sender);
    keep_client_connections(&controller, &options, &guard, &mut receiver).await;
    controller.cancel_all();
    debug!("client sentry exiting, {}", options.address);
    controller.wait().await;
    receiver.close();
    debug!("client sentry exited, {}", options.address);
}

async fn keep_client_connections(
    controller: &Context,
    options: &ClientOptionsRef,
    guard: &StreamGuarder,
    receiver: &mut Receiver,
) {
    let mut current = 0;
    let mut busy = 0;
    let max = options.max_connections;
    let max_idle = options.idle_connections;

    for _ in 0..max_idle {
        if controller.has_cancel() {
            return;
        }
        controller.spawn(start_new_tunnel(
            controller.clone(),
            guard.clone(),
            options.clone(),
            true,
        ));
        current += 1;
    }
    let mut last_report = Instant::now();

    while !controller.has_cancel() {
        let result = select! {
            r = receiver.recv() => r,
            _ = controller.wait_cancel() => {
                break;
            }
        };
        match result {
            Some(NotifyEvent::Shutdown) => {
                current -= 1;
            }
            Some(NotifyEvent::RelayStart) => {
                busy += 1;
            }
            Some(NotifyEvent::RelayFinish) => {
                busy -= 1;
            }
            None => unreachable!(),
        }
        let pending = max_idle - (current - busy);
        if current < max && pending > 0 {
            debug!(
                "spawning {} new connections to {}",
                pending, options.address
            );
            for _ in 0..pending {
                controller.spawn(start_new_tunnel(
                    controller.clone(),
                    guard.clone(),
                    options.clone(),
                    false,
                ));
            }
            current += pending;
        }
        if last_report.elapsed().as_secs() > 60 {
            info!(
                "{} alive tunnel count: total={}, idle={}",
                options.address,
                current,
                current - busy
            );
            last_report = Instant::now();
        }
    }
}

async fn start_new_tunnel(
    controller: Context,
    guard: StreamGuarder,
    options: ClientOptionsRef,
    fatal: bool,
) {
    let _guard = guard.stream_guard();
    if controller.has_cancel() {
        return;
    }
    match start_new_tunnel_impl(&controller, &guard, &options).await {
        Ok(_) => {}
        Err(e) => {
            if !fatal && can_retry_connect(&e) {
                info!(
                    "retry connect service {} cause by error: {:#}",
                    options.address, e
                );
            } else {
                if controller.has_cancel() {
                    return;
                }
                error!("connect service {} fatal: {:#}", options.address, e);
                controller.cancel_all();
            }
        }
    }
}

fn can_retry_connect(error: &errors::Error) -> bool {
    matches!(
        errors::kind_of(error),
        errors::ErrorKind::Timeout(_) | errors::ErrorKind::IoRetryAble(_)
    )
}

async fn start_new_tunnel_impl(
    controller: &Context,
    guard: &StreamGuarder,
    options: &ClientOptionsRef,
) -> Result<()> {
    let (read_half, write_half) = connect_to_server(controller, options).await?;
    handle_relay(controller, guard, read_half, write_half, &options.allows).await;
    Ok(())
}

async fn connect_to_server(
    controller: &Context,
    options: &ClientOptionsRef,
) -> Result<(ReadSession, WriteSession)> {
    let conn = options
        .address
        .connect_to(controller)
        .await
        .context("Failed to connect to tunnel server")?;
    debug!("connected to server: {}", conn);
    let (read_half, write_half) = client_handshake(
        controller,
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
    controller: &Context,
    guard: &StreamGuarder,
    read_half: ReadSession,
    write_half: WriteSession,
    allows: &HashSet<Address>,
) {
    let addr = format!("{}", read_half);
    match handle_relay_impl(controller, guard, read_half, write_half, allows).await {
        Ok((read, write)) => {
            info!(
                "stream {} disconnected and has read {} bytes and wrote {}",
                addr, read, write
            );
        }
        Err(e) => {
            if is_relay_critical_error(&e) {
                error!("stream {} relay critical error:  {:#}", addr, e);
            } else {
                info!("stream {} relay non-critical error:  {:#}", addr, e);
            }
        }
    };
}

async fn handle_relay_impl(
    controller: &Context,
    guard: &StreamGuarder,
    mut read_half: ReadSession,
    mut write_half: WriteSession,
    allows: &HashSet<Address>,
) -> Result<(usize, usize)> {
    let addr: Address = read_half
        .wait_connect_message(controller, &mut write_half)
        .await?;
    trace!("tunnel connect message has read: {}", &addr);
    if !allows.contains(&addr) {
        return Err(errors::format_err!("Address not allowed: {}", &addr));
    }
    let conn = addr
        .connect_to(controller)
        .await
        .context("Failed to connect to local service")?;
    write_half.write_connect_message(controller, &addr).await?;
    debug!("tunnel relay started: {}->{}", &read_half, addr);
    let _guard = guard.relay_guard();
    copy_encrypted_bidirectional(controller, read_half, write_half, conn.reader, conn.writer).await
}
