use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::vec::Vec;

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{self, Duration};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing::{debug, error, error_span, info, info_span, trace, warn};

use crate::config::{ListenTo, ServerConfig, Service};
use crate::errors::{Error, Result, ResultExt, whatever};
use crate::transport::Transport;
use crate::transport::{
    Context, Listener, Message, MessageKind, PlainTcpListener, PlainTcpListenerConfig,
    TlsTcpListener, copy_bidirectional_flush,
};

pub async fn start_server(context: &Context, config: ServerConfig) -> Result<()> {
    let services = config.services;
    match config.listen_to {
        ListenTo::PlainTcp(cfg) => {
            start_server_impl::<PlainTcpListener>(context, cfg, services).await
        }
        ListenTo::TlsTcp(cfg) => start_server_impl::<TlsTcpListener>(context, cfg, services).await,
    }
}

async fn start_server_impl<T: Listener>(
    context: &Context,
    config: T::Config,
    services: Vec<Service>,
) -> Result<()> {
    let pool = TunnelPool::new();
    let listener = T::new(config).await?;
    info!("server listening on {}", listener);
    context.spawn(tunnel_timer(
        context.clone(),
        listener.to_string(),
        pool.clone(),
    ));
    let listen_to = format!("{}", listener);
    context.spawn(
        serve_tunnel(context.children(), listener, pool.clone())
            .instrument(error_span!("server_tunnel", listen_to)),
    );
    for s in services.iter() {
        match Transport::parse(&s.listen_to)? {
            Transport::Tcp(addr) => {
                let listener = PlainTcpListener::new(PlainTcpListenerConfig { addr }).await?;
                let listen_to = format!("{}", listener);
                info!("service starting, listening on {}", listener);
                context.spawn(
                    serve_service(
                        context.children(),
                        listener,
                        s.connect_to.clone(),
                        pool.clone(),
                    )
                    .instrument(error_span!(
                        "service",
                        listen_to,
                        connect_to = s.connect_to
                    )),
                );
            }
        }
    }
    Ok(())
}

async fn tunnel_timer<T: Listener>(context: Context, id: String, pool: TunnelPool<T>) {
    loop {
        tokio::select! {
            _ = context.wait_cancel() => {
                return;
            },
            _ = time::sleep(Duration::from_secs(60)) => {
                info!("{} alive tunnel count: {}", id, pool.len().await);
            },
        }
    }
}

async fn serve_tunnel<T: Listener>(context: Context, listener: T, pool: TunnelPool<T>) {
    let context = &context;
    let mut index: u64 = 0;
    loop {
        index += 1;
        match context.race(listener.accept()).await {
            Ok((stream, id)) => {
                pool.clone()
                    .add(context, stream, id)
                    .instrument(info_span!("tunnel", index))
                    .await;
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

async fn serve_service<T: Listener, U: Listener>(
    context: Context,
    listener: T,
    connect_to: String,
    pool: TunnelPool<U>,
) {
    let context = &context;
    let mut index: u64 = 0;
    loop {
        index += 1;
        match context.race(listener.accept()).await {
            Ok((stream, remote_addr)) => {
                context.spawn(
                    handle_service_stream::<T, U>(
                        context.clone(),
                        stream,
                        pool.clone(),
                        connect_to.clone(),
                    )
                    .instrument(info_span!("service", index, remote_addr,)),
                );
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

async fn handle_service_stream<T: Listener, U: Listener>(
    context: Context,
    stream: T::Stream,
    pool: TunnelPool<U>,
    connect_to: String,
) {
    match handle_service_stream_impl::<T, U>(&context, stream, pool, &connect_to).await {
        Ok((read, write)) => {
            info!(
                "Stream closed and has read {} bytes and wrote {} bytes",
                read, write
            );
        }
        Err(e) => {
            if e.is_relay_critical() {
                if context.has_cancel() {
                    return;
                }
                error!("Stream relay critical error: {:#}", e);
            } else {
                info!("Stream relay non-critical error: {:#}", e);
            }
        }
    };
}

async fn handle_service_stream_impl<T: Listener, U: Listener>(
    context: &Context,
    stream: T::Stream,
    pool: TunnelPool<U>,
    connect_to: &str,
) -> Result<(u64, u64)> {
    debug!("service received a stream");
    let (remote, tunnel_addr) = context
        .timeout_default(pool.pop())
        .await
        .context("Failed to get a tunnel from pool")?;
    handle_service_relay::<T, U>(context, stream, remote, connect_to)
        .instrument(info_span!("service_relay", tunnel_addr))
        .await
}

async fn handle_service_relay<T: Listener, U: Listener>(
    context: &Context,
    stream: T::Stream,
    mut tunnel: U::Stream,
    connect_to: &str,
) -> Result<(u64, u64)> {
    info!("stream match a tunnel");
    let message = Message::connect(connect_to);
    context
        .timeout_default(tunnel.write_all(message.as_ref()))
        .await
        .context("Failed to write connect message")?;
    trace!("tunnel connect message has sent, relay started");
    let r = copy_bidirectional_flush(stream, tunnel).await?;
    Ok(r)
}

struct Session<T: Listener> {
    id: String,
    cancel_token: CancellationToken,
    receiver: Receiver<Result<T::Stream>>,
    _marker: PhantomData<T>,
}

impl<T: Listener> Ord for Session<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T: Listener> PartialEq for Session<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T: Listener> Eq for Session<T> {}

impl<T: Listener> PartialOrd for Session<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Listener> fmt::Display for Session<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<T: Listener> fmt::Debug for Session<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<T: Listener> Session<T> {
    #[tracing::instrument(skip_all)]
    async fn join(mut self) -> Result<T::Stream> {
        self.cancel_token.cancel();
        self.receiver.recv().await.unwrap()
    }
}

struct TunnelPool<T: Listener> {
    inner: Arc<TunnelPoolInner<T>>,
}

impl<T: Listener> Clone for TunnelPool<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct TunnelPoolInner<T: Listener> {
    sessions: Mutex<BTreeMap<String, Session<T>>>,
    notify: Notify,
    requires: AtomicI32,
}

impl<T: Listener> TunnelPool<T> {
    fn new() -> Self {
        let inner = Arc::new(TunnelPoolInner {
            sessions: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
            requires: AtomicI32::new(0),
        });
        Self { inner }
    }

    async fn add(self, context: &Context, stream: T::Stream, id: String) {
        info!("tunnel connected");
        let cancel_token = CancellationToken::new();
        let (sender, receiver) = mpsc::channel(1);
        let sender_token = cancel_token.clone();
        let session = Session::<T> {
            id: id.clone(),
            cancel_token,
            receiver,
            _marker: PhantomData,
        };
        self.inner.sessions.lock().await.insert(id.clone(), session);
        self.inner.notify.notify_one();
        let alive_ctx = context.clone();
        context.spawn(async move {
            let r = keep_alive::<T>(alive_ctx, sender_token, &id, stream).await;
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
        self.inner.sessions.lock().await.remove(id);
    }

    async fn len(&self) -> usize {
        self.inner.sessions.lock().await.len()
    }

    pub async fn pop(&self) -> Result<(T::Stream, String)> {
        let start = Instant::now();
        let r = self
            .pop_impl()
            .instrument(info_span!("pop", elapsed = %start.elapsed().as_millis()))
            .await;
        let elapsed = start.elapsed();
        if elapsed > Duration::from_millis(5) {
            warn!("match a tunnel took too long: {:?}", elapsed);
        }
        r
    }

    async fn pop_impl(&self) -> Result<(T::Stream, String)> {
        loop {
            let mut sessions = self.inner.sessions.lock().await;
            let result = sessions.pop_first();
            let is_empty = sessions.is_empty();
            drop(sessions);

            match result {
                Some((id, session)) => {
                    trace!("pop a session: {}", session);
                    let mut session = session.join().await?;
                    let n = self.inner.requires.load(Ordering::Acquire);
                    if n > 0 || is_empty {
                        self.inner.requires.fetch_sub(n, Ordering::Release);
                        if is_empty {
                            Message::require(n + 1).write_to(&mut session).await?;
                        } else {
                            Message::require(n).write_to(&mut session).await?;
                        }
                    }
                    return Ok((session, id));
                }
                None => {
                    self.inner.requires.fetch_add(1, Ordering::Release);
                    self.inner.notify.notified().await;
                }
            }
        }
    }
}

async fn keep_alive<T: Listener>(
    context: Context,
    stopped: CancellationToken,
    id: &String,
    mut stream: T::Stream,
) -> Result<T::Stream> {
    let interval = &mut time::interval(Duration::from_secs(5));
    interval.reset();
    let mut message = Message::ping();
    loop {
        tokio::select! {
            _ = stopped.cancelled() => {
                return Ok(stream);
            }
            _ = interval.tick() => {
                trace!("keep alive ping: {}", id);
                stream.write_all(message.as_ref()).await?;
                message.read_from_inplace(&mut stream).await?;
                if message.get_type() != MessageKind::Ping {
                    error!("keep alive ping received invalid message type: {:?}", message.get_type());
                    return Err(whatever!("Invalid message type: {:?}", message.get_type()));
                }
                trace!("keep alive success: {}", id);
                interval.reset();
            },
            _ = context.wait_cancel() => {
                return Err(Error::cancel());
            },
        }
    }
}
