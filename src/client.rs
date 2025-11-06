use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info};
use tokio::select;
use tokio::time::sleep;

use crate::config::ClientConfig;
use crate::encryption::client_handshake;
use crate::encryption::copy_encrypted_bidirectional;
use crate::encryption::{ReadSession, WriteSession};
use crate::encryption::{decode_signing_key, decode_verifying_key};
use crate::transport::{Address, Controller, NotifyEvent, Receiver};

struct ClientOptions {
    address: Address,
    verifier: VerifyingKey,
    signer: SigningKey,
    allows: HashSet<Address>,
    max_connections: i32,
    idle_connections: i32,
}

type ClientOptionsRef = Arc<ClientOptions>;

pub async fn start_client(controller: Controller, cfg: &ClientConfig) -> Result<()> {
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

    let _ = connect_to_server(controller.clone(), options.clone()).await?;
    let (controller_children, receiver) = controller.children();

    controller.spawn(service_connection_sentry(
        controller_children.clone(),
        options,
        receiver,
    ));
    Ok(())
}

async fn service_connection_sentry(
    controller: Controller,
    options: ClientOptionsRef,
    mut receiver: Receiver,
) {
    let mut current = 0;
    let mut busy = 0;
    let max = options.max_connections;
    let max_idle = options.idle_connections;
    let controller = &controller;

    for _ in 0..max_idle {
        if controller.has_shutdown() {
            return;
        }
        controller.spawn(start_new_tunnel_silent(
            controller.clone(),
            options.clone(),
            true,
        ));
        current += 1;
    }

    loop {
        let fut = receiver.recv();
        let result = select! {
            r = fut => r,
            _ = controller.wait_shutdown() => {
                return;
            }
            _ = sleep(Duration::from_millis(1000)) => {
                None
            }
        };
        if controller.has_shutdown() {
            return;
        }
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
                controller.spawn(start_new_tunnel_silent(
                    controller.clone(),
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

async fn start_new_tunnel_silent(controller: Controller, options: ClientOptionsRef, fatal: bool) {
    if controller.has_shutdown() {
        return;
    }
    match start_new_tunnel(controller.clone(), options.clone()).await {
        Ok(_) => {}
        Err(e) => {
            if !fatal && is_retry_able_error(&e) {
                info!(
                    "retry connect service {} cause by error: {}",
                    options.address, e
                );
            } else {
                error!("connect service {} fatal: {}", options.address, &e);
                controller.shutdown();
            }
        }
    }
}

fn is_retry_able_error(error: &anyhow::Error) -> bool {
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

async fn start_new_tunnel(controller: Controller, options: ClientOptionsRef) -> Result<()> {
    let _guard = controller.session_guard();
    let (mut read_half, mut write_half) =
        connect_to_server(controller.clone(), options.clone()).await?;
    handle_stream_silent(controller, &mut read_half, &mut write_half, &options.allows).await;
    Ok(())
}

async fn connect_to_server(
    _controller: Controller,
    options: ClientOptionsRef,
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

async fn handle_stream_silent(
    controller: Controller,
    read_half: &mut ReadSession,
    write_half: &mut WriteSession,
    allows: &HashSet<Address>,
) {
    match handle_stream(controller, read_half, write_half, allows).await {
        Ok((read, write)) => {
            info!("stream has read {} bytes and wrote {}", read, write);
        }
        Err(e) => {
            error!("stream transfer error: {}, {}", e, read_half);
        }
    };
}

async fn handle_stream(
    controller: Controller,
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
    Ok(copy_encrypted_bidirectional(
        controller,
        read_half,
        write_half,
        &mut conn.reader,
        &mut conn.writer,
    )
    .await)
}
