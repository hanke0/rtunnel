use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use log::{debug, error, info, trace};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;

use crate::config::ServerConfig;
use crate::config::build_listener;
use crate::errors::{Error, Result, ResultExt};
use crate::logger::debug_spend;
use crate::transport::{Context, Listener, Message, MessageKind, Stream, copy_bidirectional_flush};
use crate::whatever;

struct ServerOptions {
    pool: TunnelPool,
}

impl ServerOptions {
    #[inline]
    async fn pop_stream(&self) -> Result<Stream> {
        self.pool.pop().await
    }

    #[inline]
    async fn push_stream(&self, context: Context, stream: Stream) {
        self.pool.clone().add(context, stream).await
    }
}

struct Session {
    id: String,
    cancel_token: CancellationToken,
    receiver: Receiver<Result<Stream>>,
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
    async fn join(mut self) -> Result<Stream> {
        debug_spend!(
            {
                self.cancel_token.cancel();
                self.receiver.recv().await.unwrap()
            },
            "session {} join",
            self.id
        )
    }
}

async fn keep_alive(
    context: Context,
    stopped: CancellationToken,
    mut stream: Stream,
) -> Result<Stream> {
    let interval = &mut time::interval(Duration::from_secs(5));
    interval.reset();
    let mut message = Message::ping();
    loop {
        tokio::select! {
            _ = stopped.cancelled() => {
                return Ok(stream);
            }
            _ = interval.tick() => {
                trace!("keep alive ping sending: {}", stream);
                stream.write_all(message.as_ref()).await?;
                trace!("keep alive ping receiving: {}", stream);
                message.read_from_inplace(&mut stream).await?;
                if message.get_type() != MessageKind::Ping {
                    error!("keep alive ping received invalid message type: {:?}", message.get_type());
                    return Err(whatever!("Invalid message type: {:?}", message.get_type()));
                }
                trace!("keep alive success: {}", stream);
                interval.reset();
            },
            _ = context.wait_cancel() => {
                return Err(Error::cancel());
            },
        }
    }
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

    async fn add(self, context: Context, stream: Stream) {
        let cancel_token = CancellationToken::new();
        let id = format!("{}", stream);
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
            let r = keep_alive(context, sender_token, stream).await;
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

    pub async fn pop(&self) -> Result<Stream> {
        loop {
            match self.0.sessions.lock().await.pop_first() {
                Some((_, session)) => {
                    trace!("pop a session: {}", session);
                    return session.join().await;
                }
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
    let listener = build_listener(cfg.listen_to.clone()).await?;
    info!("server listening on {}", listener);
    let options = &Arc::new(ServerOptions {
        pool: TunnelPool::new(),
    });
    context.spawn(tunnel_timer(
        context.clone(),
        options.clone(),
        cfg.listen_to.to_string(),
    ));
    context.spawn(start_tunnel(context.children(), listener, options.clone()));
    for s in cfg.services.iter() {
        let listener = Listener::bind(&s.listen_to).await?;
        info!("service starting, listening on {}", listener);
        context.spawn(start_service(
            context.children(),
            listener,
            s.connect_to.clone(),
            options.clone(),
        ));
    }
    Ok(())
}

async fn tunnel_timer(context: Context, options: ServerOptionsRef, addr: String) {
    if !log::log_enabled!(log::Level::Info) {
        return;
    }
    loop {
        tokio::select! {
            _ = context.wait_cancel() => {
                return;
            },
            _ = time::sleep(Duration::from_secs(60)) => {
                info!("{} alive tunnel count: {}", addr, options.pool.len().await);
            },
        }
    }
}

async fn start_tunnel(context: Context, mut listener: Listener, options: ServerOptionsRef) {
    let context = &context;
    loop {
        match listener.accept(context).await {
            Ok(stream) => {
                debug!("new tunnel client connected: {}", stream);
                options.push_stream(context.clone(), stream).await;
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

async fn start_service(
    context: Context,
    mut listener: Listener,
    connect_to: String,
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
                    connect_to.clone(),
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
    connect_to: String,
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
    connect_to: &str,
) -> Result<(u64, u64)> {
    let remote = get_a_useable_connection(context, options, &mut stream, connect_to).await?;
    let r = copy_bidirectional_flush(stream, remote).await?;
    Ok(r)
}

async fn get_a_useable_connection(
    context: &Context,
    options: &ServerOptionsRef,
    stream: &mut Stream,
    connect_to: &str,
) -> Result<Stream> {
    let mut remote = context
        .timeout_default(options.pop_stream())
        .await
        .context("Failed to get a tunnel from pool")?;
    trace!("Stream got a tunnel: {}->{}", stream, connect_to);
    let mut message = Message::connect(connect_to);
    context
        .timeout_default(remote.write_all(message.as_ref()))
        .await
        .context("Failed to write connect message")?;
    trace!(
        "tunnel connect message has sent, wait connect message reply: {}->{}",
        stream, connect_to,
    );
    context
        .timeout_default(message.wait_connect_message(context, &mut remote))
        .await
        .context("Failed to wait connect message")?;
    trace!(
        "Tunnel connect message has received, relay started: {}->{}",
        stream, remote,
    );
    Ok(remote)
}
