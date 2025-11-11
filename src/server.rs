use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{self, Duration, sleep};
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;
use crate::encryption::{
    ReadSession, WriteSession, copy_encrypted_bidirectional, server_handshake,
};
use crate::encryption::{decode_signing_key, decode_verifying_key};
use crate::errors::{
    self, Result, cancel_error, is_accept_critical_error, is_relay_critical_error,
};
use crate::transport::{Address, Controller, Listener, Stream};

struct ServerOptions {
    verifier: VerifyingKey,
    signer: SigningKey,
    pool: TunnelPool,
}

impl ServerOptions {
    #[inline]
    async fn pop_stream(&self) -> Result<(ReadSession, WriteSession)> {
        self.pool.pop().await
    }

    #[inline]
    async fn push_stream(&self, controller: Controller, reader: ReadSession, writer: WriteSession) {
        self.pool.clone().add(controller, reader, writer).await
    }
}

struct Session {
    id: String,
    cancel_token: CancellationToken,
    receiver: Receiver<Result<(ReadSession, WriteSession)>>,
}

impl Ord for Session {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Session {}

impl PartialOrd for Session {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        self.receiver.close();
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl Session {
    async fn join(mut self) -> Result<(ReadSession, WriteSession)> {
        self.cancel_token.cancel();
        self.receiver.recv().await.unwrap()
    }
}

async fn keep_alive(
    controller: Controller,
    stopped: CancellationToken,
    mut reader: ReadSession,
    mut writer: WriteSession,
) -> Result<(ReadSession, WriteSession)> {
    let interval = &mut time::interval(Duration::from_secs(5));
    while !stopped.is_cancelled() {
        tokio::select! {
            _ = controller.wait_cancel() => {
                return Err(cancel_error());
            },
            _ = stopped.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                writer.write_ping(&controller).await?;
                reader.read_ping(&controller).await?;
                interval.reset();
            }
        }
    }
    Ok((reader, writer))
}

struct TunnelPool(Arc<TunnelPoolInner>);

struct TunnelPoolInner {
    sessions: Mutex<BTreeMap<String, Session>>,
}

impl Clone for TunnelPool {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl TunnelPool {
    fn new() -> Self {
        Self(Arc::new(TunnelPoolInner {
            sessions: Mutex::new(BTreeMap::new()),
        }))
    }

    async fn add(self, controller: Controller, reader: ReadSession, writer: WriteSession) {
        let cancel_token = CancellationToken::new();
        let id = format!("{}", reader);
        let (sender, receiver) = mpsc::channel(1);
        let sender_token = cancel_token.clone();
        let session = Session {
            id: id.clone(),
            cancel_token,
            receiver,
        };
        self.0.sessions.lock().await.insert(id.clone(), session);
        tokio::spawn(async move {
            let r = keep_alive(controller, sender_token, reader, writer).await;
            match r {
                Ok(_) => {
                    sender.send(r).await.unwrap();
                }
                Err(e) => {
                    if is_relay_critical_error(&e) {
                        error!("{} keep alive critical error: {}", id, e);
                    } else {
                        info!("{} keep alive non-critical error: {}", id, e);
                    }
                    self.remove(&id).await;
                }
            }
        });
    }

    async fn remove(&self, id: &String) {
        self.0.sessions.lock().await.remove(id);
    }

    pub async fn pop(&self) -> Result<(ReadSession, WriteSession)> {
        for _ in 0..3 {
            match self.0.sessions.lock().await.pop_first() {
                Some((_, session)) => return session.join().await,
                None => {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(errors::format_err!("pool is empty"))
    }
}

type ServerOptionsRef = Arc<ServerOptions>;

pub async fn start_server(controller: &Controller, cfg: &ServerConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.client_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let listener = cfg.listen.listen_to(controller).await?;
    info!("server listening on {}", cfg.listen);
    let options = &Arc::new(ServerOptions {
        verifier,
        signer,
        pool: TunnelPool::new(),
    });
    controller.spawn(start_tunnel(
        controller.children(),
        listener,
        options.clone(),
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

async fn start_tunnel(controller: Controller, mut listener: Listener, options: ServerOptionsRef) {
    let controller = &controller;
    loop {
        match listener.accept(controller).await {
            Ok(stream) => {
                controller.spawn(handle_tunnel(controller.clone(), stream, options.clone()));
            }
            Err(e) => {
                if is_accept_critical_error(&e) {
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

async fn handle_tunnel(controller: Controller, stream: Stream, options: ServerOptionsRef) {
    let peer = stream.reader.peer_addr();
    match handle_tunnel_impl(&controller, stream, &options).await {
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
) -> Result<()> {
    let (reader, writer) = server_handshake(
        controller,
        stream.reader,
        stream.writer,
        &options.signer,
        &options.verifier,
    )
    .await?;
    options
        .push_stream(controller.clone(), reader, writer)
        .await;
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
                if is_accept_critical_error(&e) {
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

async fn handle_service_stream(
    controller: Controller,
    stream: Stream,
    options: ServerOptionsRef,
    connect_to: Address,
) {
    let debug = format!("{}", stream);
    debug!("new service stream connected: {}", debug);
    match handle_service_stream_impl(&controller, stream, &options, &connect_to).await {
        Ok((read, write)) => {
            info!(
                "stream {} closed and has read {} bytes and wrote {} bytes",
                debug, read, write
            );
        }
        Err(e) => {
            if is_relay_critical_error(&e) {
                if controller.has_cancel() {
                    return;
                }
                error!("stream {} relay critical error: {:#}", debug, e);
            } else {
                info!("stream {} relay non-critical error: {:#}", debug, e);
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
    Err(errors::format_err!("failed to get a useable connection"))
}

async fn get_a_useable_connection_impl(
    controller: &Controller,
    options: &ServerOptionsRef,
    stream: &mut Stream,
    connect_to: &Address,
) -> Result<(ReadSession, WriteSession)> {
    let (mut read_half, mut write_half) = options.pop_stream().await?;

    debug!("stream got a tunnel: {}->{}", stream, read_half);
    write_half
        .write_connect_message(controller, connect_to)
        .await?;
    debug!(
        "tunnel connect message has sent, wait connect message reply: {}->{}",
        stream, read_half,
    );
    read_half
        .wait_connect_message(controller, &mut write_half)
        .await?;
    debug!(
        "tunnel connect message has received, relay started: {}->{}",
        stream, read_half,
    );
    Ok((read_half, write_half))
}
