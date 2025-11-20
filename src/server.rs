use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, error, info, trace};
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;
use crate::encryption::{self, decode_signing_key, decode_verifying_key};
use crate::encryption::{
    ReadSession, WriteSession, copy_encrypted_bidirectional, server_handshake,
};
use crate::errors::{Error, Result, ResultExt};
use crate::transport::{Address, Context, Listener, Stream};

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
    async fn push_stream(&self, context: Context, reader: ReadSession, writer: WriteSession) {
        self.pool.clone().add(context, reader, writer).await
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
    context: Context,
    stopped: CancellationToken,
    mut reader: ReadSession,
    mut writer: WriteSession,
) -> Result<(ReadSession, WriteSession)> {
    let interval = &mut time::interval(Duration::from_secs(5));
    interval.reset();
    while !stopped.is_cancelled() {
        tokio::select! {
            _ = context.wait_cancel() => {
                return Err(Error::cancel());
            },
            _ = stopped.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                encryption::keep_alive(&context,&mut reader, &mut writer).await?;
                interval.reset();
            }
        }
    }
    Ok((reader, writer))
}

struct TunnelPool(Arc<TunnelPoolInner>);

struct TunnelPoolInner {
    sessions: Mutex<BTreeMap<String, Session>>,
    notify: Notify,
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
            notify: Notify::new(),
        }))
    }

    async fn add(self, context: Context, reader: ReadSession, writer: WriteSession) {
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
        self.0.notify.notify_last();
        tokio::spawn(async move {
            let r = keep_alive(context, sender_token, reader, writer).await;
            match r {
                Ok(_) => {
                    sender.send(r).await.unwrap();
                }
                Err(err) => {
                    if err.is_relay_critical() {
                        error!("{} keep alive critical error: {:#}", id, err);
                    } else {
                        info!("{} keep alive non-critical error: {:#}", id, err);
                    }
                    self.remove(&id).await;
                    debug!("{} removed from pool", id);
                }
            }
        });
    }

    async fn remove(&self, id: &String) {
        self.0.sessions.lock().await.remove(id);
    }

    async fn len(&self) -> usize {
        self.0.sessions.lock().await.len()
    }

    pub async fn pop(&self) -> Result<(ReadSession, WriteSession)> {
        loop {
            match self.0.sessions.lock().await.pop_first() {
                Some((_, session)) => return session.join().await,
                None => {
                    self.0.notify.notified().await;
                }
            }
        }
    }
}

type ServerOptionsRef = Arc<ServerOptions>;

/// Starts a tunnel server with the given configuration.
///
/// This function sets up listeners for tunnel connections and service endpoints,
/// manages the tunnel connection pool, and handles incoming connections.
pub async fn start_server(context: &Context, cfg: &ServerConfig) -> Result<()> {
    let verifier = decode_verifying_key(&cfg.client_public_key)?;
    let signer = decode_signing_key(&cfg.private_key)?;

    let listener = cfg.listen.listen_to(context).await?;
    info!("server listening on {}", cfg.listen);
    let options = &Arc::new(ServerOptions {
        verifier,
        signer,
        pool: TunnelPool::new(),
    });
    context.spawn(tunnel_timer(context.clone(), options.clone(), cfg.listen));
    context.spawn(start_tunnel(context.children(), listener, options.clone()));
    for s in cfg.services.iter() {
        let listener = s.bind_to.listen_to(context).await?;
        info!("service starting, listening on {}", s.bind_to);
        context.spawn(start_service(
            context.children(),
            listener,
            s.connect_to,
            options.clone(),
        ));
    }
    Ok(())
}

async fn tunnel_timer(context: Context, options: ServerOptionsRef, address: Address) {
    if !log::log_enabled!(log::Level::Info) {
        return;
    }
    loop {
        tokio::select! {
            _ = context.wait_cancel() => {
                return;
            },
            _ = time::sleep(Duration::from_secs(60)) => {
                info!("{} alive tunnel count: {}", address, options.pool.len().await);
            },
        }
    }
}

async fn start_tunnel(context: Context, mut listener: Listener, options: ServerOptionsRef) {
    let context = &context;
    loop {
        match listener.accept(context).await {
            Ok(stream) => {
                context.spawn(handle_tunnel(context.clone(), stream, options.clone()));
            }
            Err(e) => {
                if e.is_accept_critical() {
                    if context.has_cancel() {
                        return;
                    }
                    error!("listener accept error: {:#}", e);
                    context.cancel_all();
                    break;
                }
                info!("listener accept error, retrying: {:#}", e);
            }
        }
    }
    context.cancel_all();
    context.wait().await;
}

async fn handle_tunnel(context: Context, stream: Stream, options: ServerOptionsRef) {
    let addr = format!("{}", stream);
    match handle_tunnel_impl(&context, stream, &options).await {
        Ok(_) => {
            debug!("new tunnel session created: {}", addr);
        }
        Err(e) => {
            error!("tunnel session {} establish error: {:#}", addr, e);
        }
    }
}

async fn handle_tunnel_impl(
    context: &Context,
    stream: Stream,
    options: &ServerOptionsRef,
) -> Result<()> {
    let (reader, writer) = server_handshake(
        context,
        stream.reader,
        stream.writer,
        &options.signer,
        &options.verifier,
    )
    .await?;
    options.push_stream(context.clone(), reader, writer).await;
    Ok(())
}

async fn start_service(
    context: Context,
    mut listener: Listener,
    connect_to: Address,
    options: ServerOptionsRef,
) {
    let context = &context;
    loop {
        match listener.accept(context).await {
            Ok(stream) => {
                context.spawn(handle_service_stream(
                    context.clone(),
                    stream,
                    options.clone(),
                    connect_to,
                ));
            }
            Err(e) => {
                if e.is_accept_critical() {
                    if !context.has_cancel() {
                        error!("listener accept error: {:#}", e);
                    }
                    break;
                }
                info!("listener accept error, retrying: {:#}", e);
            }
        }
    }
    context.cancel_all();
    context.wait().await;
}

async fn handle_service_stream(
    context: Context,
    stream: Stream,
    options: ServerOptionsRef,
    connect_to: Address,
) {
    let debug = format!("{}", stream);
    debug!("new service stream connected: {}", debug);
    match handle_service_stream_impl(&context, stream, &options, &connect_to).await {
        Ok((read, write)) => {
            info!(
                "Stream {} closed and has read {} bytes and wrote {} bytes",
                debug, read, write
            );
        }
        Err(e) => {
            if e.is_relay_critical() {
                if context.has_cancel() {
                    return;
                }
                error!("Stream {} relay critical error: {:#}", debug, e);
            } else {
                info!("Stream {} relay non-critical error: {:#}", debug, e);
            }
        }
    };
}

async fn handle_service_stream_impl(
    context: &Context,
    mut stream: Stream,
    options: &ServerOptionsRef,
    connect_to: &Address,
) -> Result<(usize, usize)> {
    let (read_half, write_half) =
        get_a_useable_connection(context, options, &mut stream, connect_to).await?;

    copy_encrypted_bidirectional(context, read_half, write_half, stream.reader, stream.writer).await
}

async fn get_a_useable_connection(
    context: &Context,
    options: &ServerOptionsRef,
    stream: &mut Stream,
    connect_to: &Address,
) -> Result<(ReadSession, WriteSession)> {
    let (mut read_half, mut write_half) = context
        .timeout_default(options.pop_stream())
        .await
        .context("Failed to get a tunnel from pool")?;
    trace!("Stream got a tunnel: {}->{}", stream, read_half);

    context
        .timeout_default(write_half.write_connect_message(context, connect_to))
        .await
        .context("Failed to write connect message")?;
    trace!(
        "tunnel connect message has sent, wait connect message reply: {}->{}",
        stream, read_half,
    );
    context
        .timeout_default(read_half.wait_connect_message(context, &mut write_half))
        .await
        .context("Failed to wait connect message")?;
    trace!(
        "Tunnel connect message has received, relay started: {}->{}",
        stream, read_half,
    );
    Ok((read_half, write_half))
}
