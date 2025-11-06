use std::sync::Arc;

use anyhow::{Error, Result};
use async_channel;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info};

use crate::config::ServerConfig;
use crate::encryption::{
    ReadSession, WriteSession, copy_encrypted_bidirectional, server_handshake,
};
use crate::encryption::{decode_signing_key, decode_verifying_key};
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

pub async fn start_server(controller: Controller, cfg: &ServerConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.client_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let listener = cfg.listen.listen_to().await?;
    info!("server listening on {}", cfg.listen);
    let (sender, receiver) = async_channel::unbounded();
    let options = &Arc::new(ServerOptions {
        verifier,
        signer,
        receiver,
    });
    controller.spawn(start_server_listener(
        controller.clone(),
        listener,
        options.clone(),
        sender,
    ));
    for s in cfg.services.iter() {
        let listener = s.bind_to.listen_to().await?;
        info!("service starting, listening on {}", s.bind_to);
        controller.spawn(start_service(
            controller.clone(),
            listener,
            s.connect_to,
            options.clone(),
        ));
    }
    Ok(())
}

async fn start_server_listener(
    controller: Controller,
    mut listener: Listener,
    options: ServerOptionsRef,
    sender: SessionSender,
) {
    let controller = &controller;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                controller.spawn(handle_server_stream_silent(
                    controller.clone(),
                    stream,
                    options.clone(),
                    sender.clone(),
                ));
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    error!("listener accept error: {}", e);
                    return;
                }
                info!("listener accept error, retrying: {}", e);
            }
        }
    }
}

async fn handle_server_stream_silent(
    _controller: Controller,
    stream: Stream,
    options: ServerOptionsRef,
    sender: SessionSender,
) {
    let peer = stream.reader.peer_addr();
    match handle_server_stream(stream, &options, &sender).await {
        Ok(_) => {
            debug!("new tunnel session created: {}", peer);
        }
        Err(e) => {
            error!("tunnel session {} establish error: {}", peer, e);
        }
    }
}

async fn handle_server_stream(
    stream: Stream,
    options: &ServerOptionsRef,
    sender: &SessionSender,
) -> Result<()> {
    let rsp = server_handshake(
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
) -> Result<()> {
    let controller = &controller;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                controller.spawn(handle_service_stream_silent(
                    controller.clone(),
                    stream,
                    options.clone(),
                    connect_to,
                ));
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    error!("listener accept error: {}", e);
                    return Result::Err(Error::from(e));
                }
                info!("listener accept error, retrying: {}", e);
            }
        }
    }
}

async fn handle_service_stream_silent(
    controller: Controller,
    stream: Stream,
    options: ServerOptionsRef,
    connect_to: Address,
) {
    let addr = stream.peer_addr();
    let local_addr = stream.local_addr();
    debug!("new service stream connected: {}->{}", addr, local_addr);
    match handle_service_stream(controller, stream, options, connect_to).await {
        Ok((read, write)) => {
            info!(
                "stream {} has read {} bytes and wrote {} bytes",
                addr, read, write
            );
        }
        Err(e) => {
            error!("stream {} relay error: {}", addr, e);
        }
    };
}

async fn handle_service_stream(
    controller: Controller,
    mut stream: Stream,
    options: ServerOptionsRef,
    connect_to: Address,
) -> Result<(usize, usize)> {
    let (mut read_half, mut write_half) = options.pop_stream().await;
    debug!(
        "stream got a tunnel: {}->{}",
        stream.peer_addr(),
        stream.local_addr()
    );
    write_half.write_connect_message(connect_to).await?;
    debug!(
        "tunnel connect message has sent, stream relay started: {}->{}",
        stream.peer_addr(),
        stream.local_addr()
    );
    return Ok(copy_encrypted_bidirectional(
        controller,
        &mut read_half,
        &mut write_half,
        &mut stream.reader,
        &mut stream.writer,
    )
    .await);
}
