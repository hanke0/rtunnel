use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info};
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::config::ClientConfig;
use crate::encryption::client_handshake;
use crate::encryption::copy_encrypted_bidirectional;
use crate::encryption::{ReadSession, WriteSession};
use crate::encryption::{decode_signing_key, decode_verifying_key};
use crate::transport::{Address, Controller};

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

pub async fn start_client(controller: &Controller, cfg: &ClientConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.server_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;
    let mut allows = HashSet::new();
    for service in cfg.services.iter() {
        allows.insert(service.connect_to);
    }

    let options = Arc::new(ClientOptions {
        address: cfg.server_address,
        verifier,
        signer,
        allows,
        max_connections: cfg.max_connections,
        idle_connections: cfg.idle_connections,
    });

    let _ = connect_to_server(controller, &options).await?;

    controller.spawn(start_client_sentry(controller.children(), options));
    Ok(())
}

async fn start_client_sentry(controller: Controller, options: ClientOptionsRef) {
    let (sender, mut receiver) = unbounded_channel();
    let guard = StreamGuarder::new(sender);
    keep_client_connections(&controller, &options, guard, &mut receiver).await;
    controller.cancel_all();
    controller.wait().await;
    receiver.close();
    debug!("client sentry exited, {}", options.address)
}

async fn keep_client_connections(
    controller: &Controller,
    options: &ClientOptionsRef,
    guard: StreamGuarder,
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

    while !controller.has_cancel() {
        let fut = receiver.recv();
        let result = select! {
            r = fut => r,
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
            None => (),
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
            // give the new connections a chance to start before checking
            // wait counter to settle.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn start_new_tunnel(
    controller: Controller,
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
                error!("connect service {} fatal: {:#}", options.address, e);
                controller.cancel();
            }
        }
    }
}

fn can_retry_connect(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            match io_error.kind() {
                io::ErrorKind::ConnectionRefused => return false,
                _ => return true,
            }
        }
    }
    return true;
}

async fn start_new_tunnel_impl(
    controller: &Controller,
    guard: &StreamGuarder,
    options: &ClientOptionsRef,
) -> Result<()> {
    let (mut read_half, mut write_half) = connect_to_server(controller, options).await?;
    handle_tunnel(
        controller,
        guard,
        &mut read_half,
        &mut write_half,
        &options.allows,
    )
    .await;
    Ok(())
}

async fn connect_to_server(
    _controller: &Controller,
    options: &ClientOptionsRef,
) -> Result<(ReadSession, WriteSession)> {
    let conn = options.address.connect_to().await?;
    let peer_addr = conn.reader.peer_addr();
    let local_addr = conn.reader.local_addr();
    debug!("tunnel connected: {}->{}", peer_addr, local_addr);
    let (read_half, write_half) =
        client_handshake(conn.reader, conn.writer, &options.signer, &options.verifier).await?;
    debug!("tunnel established: {}->{}", peer_addr, local_addr);
    return Ok((read_half, write_half));
}

async fn handle_tunnel(
    controller: &Controller,
    guard: &StreamGuarder,
    read_half: &mut ReadSession,
    write_half: &mut WriteSession,
    allows: &HashSet<Address>,
) {
    match handle_tunnel_impl(&controller, guard, read_half, write_half, allows).await {
        Ok((read, write)) => {
            info!("stream has read {} bytes and wrote {}", read, write);
        }
        Err(e) => {
            if is_critical_relay_error(&e) {
                error!("stream {} transfer error:  {:#}", read_half, e);
            } else {
                info!("stream {} transfer error:  {:#}", read_half, e);
            }
        }
    };
}

fn is_critical_relay_error(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            match io_error.kind() {
                io::ErrorKind::UnexpectedEof => return false,
                _ => return true,
            }
        }
    }
    return true;
}

async fn handle_tunnel_impl(
    controller: &Controller,
    guard: &StreamGuarder,
    read_half: &mut ReadSession,
    write_half: &mut WriteSession,
    allows: &HashSet<Address>,
) -> Result<(usize, usize)> {
    let addr = read_half.read_connect_message().await?;
    debug!("tunnel connect message has read: {}", &addr);
    if !allows.contains(&addr) {
        return Err(anyhow!("Address not allowed: {}", &addr));
    }
    let mut conn = addr.connect_to().await?;
    debug!("tunnel relay established: {}->{}", &read_half, addr);
    let _guard = guard.relay_guard();
    Ok(copy_encrypted_bidirectional(
        controller,
        read_half,
        write_half,
        &mut conn.reader,
        &mut conn.writer,
    )
    .await)
}
