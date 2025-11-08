use std::io;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use async_channel;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info};
use tokio::time::timeout;

use crate::config::ServerConfig;
use crate::encryption::{
    ReadSession, WriteSession, copy_encrypted_bidirectional, server_handshake,
};
use crate::encryption::{decode_signing_key, decode_verifying_key, is_relay_critical_error};
use crate::transport::{Address, Controller, Listener, Stream};

struct ServerOptions {
    verifier: VerifyingKey,
    signer: SigningKey,
    receiver: SessionReceiver,
}

type SessionReceiver = async_channel::Receiver<(ReadSession, WriteSession)>;
type SessionSender = async_channel::Sender<(ReadSession, WriteSession)>;

impl ServerOptions {
    async fn pop_stream(&self) -> (ReadSession, WriteSession) {
        self.receiver.recv().await.unwrap()
    }
}

type ServerOptionsRef = Arc<ServerOptions>;

pub async fn start_server(controller: &Controller, cfg: &ServerConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.client_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let listener = cfg.listen.listen_to(controller).await?;
    info!("server listening on {}", cfg.listen);
    let (sender, receiver) = async_channel::unbounded();
    let options = &Arc::new(ServerOptions {
        verifier,
        signer,
        receiver,
    });
    controller.spawn(start_tunnel(
        controller.children(),
        listener,
        options.clone(),
        sender,
    ));
    for s in cfg.services.iter() {
        let listener = s.bind_to.listen_to(controller).await?;
        info!("service starting, listening on {}", s.bind_to);
        controller.spawn(start_service(
            controller.children(),
            listener,
            s.connect_to,
            options.clone(),
        ));
    }
    Ok(())
}

async fn start_tunnel(
    controller: Controller,
    mut listener: Listener,
    options: ServerOptionsRef,
    sender: SessionSender,
) {
    let controller = &controller;
    loop {
        match listener.accept(controller).await {
            Ok(stream) => {
                controller.spawn(handle_tunnel(
                    controller.clone(),
                    stream,
                    options.clone(),
                    sender.clone(),
                ));
            }
            Err(e) => {
                if is_critical_listener_error(&e) {
                    if controller.has_cancel() {
                        return;
                    }
                    error!("listener accept error: {:#}", e);
                    controller.cancel_all();
                    break;
                }
                info!("listener accept error, retrying: {:#}", e);
            }
        }
    }
    controller.cancel_all();
    controller.wait().await;
}

async fn handle_tunnel(
    controller: Controller,
    stream: Stream,
    options: ServerOptionsRef,
    sender: SessionSender,
) {
    let peer = stream.reader.peer_addr();
    match handle_tunnel_impl(&controller, stream, &options, &sender).await {
        Ok(_) => {
            debug!("new tunnel session created: {}", peer);
        }
        Err(e) => {
            error!("tunnel session {} establish error: {:#}", peer, e);
        }
    }
}

async fn handle_tunnel_impl(
    controller: &Controller,
    stream: Stream,
    options: &ServerOptionsRef,
    sender: &SessionSender,
) -> Result<()> {
    let rsp = server_handshake(
        controller,
        stream.reader,
        stream.writer,
        &options.signer,
        &options.verifier,
    )
    .await?;
    sender.send(rsp).await?;
    Ok(())
}

async fn start_service(
    controller: Controller,
    mut listener: Listener,
    connect_to: Address,
    options: ServerOptionsRef,
) {
    let controller = &controller;
    loop {
        match listener.accept(controller).await {
            Ok(stream) => {
                controller.spawn(handle_service_stream(
                    controller.clone(),
                    stream,
                    options.clone(),
                    connect_to,
                ));
            }
            Err(e) => {
                if is_critical_listener_error(&e) {
                    if controller.has_cancel() {
                        return;
                    }
                    error!("listener accept error: {:#}", e);
                    controller.cancel_all();
                    break;
                }
                info!("listener accept error, retrying: {:#}", e);
            }
        }
    }
    controller.cancel_all();
    controller.wait().await;
}

fn is_critical_listener_error(io_error: &io::Error) -> bool {
    match io_error.kind() {
        io::ErrorKind::WouldBlock => return false,
        io::ErrorKind::Interrupted => return false,
        _ => return true,
    }
}

async fn handle_service_stream(
    controller: Controller,
    stream: Stream,
    options: ServerOptionsRef,
    connect_to: Address,
) {
    let repr = format!("{}", stream);
    debug!("new service stream connected: {}", repr);
    match handle_service_stream_impl(&controller, stream, &options, &connect_to).await {
        Ok((read, write)) => {
            info!(
                "stream {} closed and has read {} bytes and wrote {} bytes",
                repr, read, write
            );
        }
        Err(e) => {
            if is_relay_critical_error(&e) {
                error!("stream {} relay critical error: {:#}", repr, e);
            } else {
                info!("stream {} relay non-critical error: {:#}", repr, e);
            }
        }
    };
}

async fn handle_service_stream_impl(
    controller: &Controller,
    mut stream: Stream,
    options: &ServerOptionsRef,
    connect_to: &Address,
) -> Result<(usize, usize)> {
    let (mut read_half, mut write_half) =
        get_a_useable_connection(controller, options, &mut stream, connect_to).await?;

    copy_encrypted_bidirectional(
        controller,
        &mut read_half,
        &mut write_half,
        &mut stream.reader,
        &mut stream.writer,
    )
    .await
}

async fn get_a_useable_connection(
    controller: &Controller,
    options: &ServerOptionsRef,
    stream: &mut Stream,
    connect_to: &Address,
) -> Result<(ReadSession, WriteSession)> {
    for _ in 0..3 {
        match get_a_useable_connection_impl(controller, options, stream, connect_to).await {
            Ok((read_half, write_half)) => {
                return Ok((read_half, write_half));
            }
            Err(e) => {
                info!("get a useable connection error: {:#}", e);
            }
        }
    }
    Err(anyhow!("failed to get a useable connection"))
}

async fn get_a_useable_connection_impl(
    controller: &Controller,
    options: &ServerOptionsRef,
    stream: &mut Stream,
    connect_to: &Address,
) -> Result<(ReadSession, WriteSession)> {
    let (mut read_half, mut write_half) =
        match timeout(Duration::from_secs(1), options.pop_stream()).await {
            Ok(rsp) => rsp,
            Err(_) => {
                return Err(anyhow!("timeout to get a relay session after 1 second"));
            }
        };

    debug!("stream got a tunnel: {}->{}", stream, read_half);
    write_half
        .write_connect_message(controller, connect_to)
        .await?;
    debug!(
        "tunnel connect message has sent, wait connect message reply: {}->{}",
        stream, read_half,
    );
    read_half.read_connect_message(controller).await?;
    debug!(
        "tunnel connect message has received, relay started: {}->{}",
        stream, read_half,
    );
    Ok((read_half, write_half))
}
