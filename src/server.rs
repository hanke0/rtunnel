use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::vec::Vec;

use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::oneshot;
use tokio::time::{self, Duration};
use tracing::Instrument;
use tracing::{debug, error, error_span, info, info_span, trace, warn};

use crate::config::{ListenTo, ServerConfig, Service};
use crate::errors::{Error, Result, ResultExt, whatever};
use crate::transport::Transport;
use crate::transport::{
    Context, Listener, Message, MessageKind, PlainTcpListener, PlainTcpListenerConfig,
    QuicListener, TlsTcpListener, relay_bidirectional,
};

macro_rules! match_listen_to2 {
    ($context:ident, $config:ident, $cfg:ident, $typ:ty) => {
        match $config.listen_to2 {
            Some(ListenTo::PlainTcp(cfg2)) => {
                match_listen_to2!($context, $config, $cfg, $typ, Some(cfg2), PlainTcpListener)
            }
            Some(ListenTo::TlsTcp(cfg2)) => {
                match_listen_to2!($context, $config, $cfg, $typ, Some(cfg2), TlsTcpListener)
            }
            Some(ListenTo::Quic(cfg2)) => {
                match_listen_to2!($context, $config, $cfg, $typ, Some(cfg2), QuicListener)
            }
            None => {
                match_listen_to2!($context, $config, $cfg, $typ, None, QuicListener)
            }
        }
    };

    ($context:ident, $config:ident, $cfg1:ident, $typ1:ty, $cfg2:expr, $typ2:ty) => {
        start_server_impl::<$typ1, $typ2>($context, $cfg1, $cfg2, $config.services).await
    };
}

pub async fn start_server(context: &Context, config: ServerConfig) -> Result<()> {
    match config.listen_to {
        ListenTo::PlainTcp(cfg) => match_listen_to2!(context, config, cfg, PlainTcpListener),
        ListenTo::TlsTcp(cfg) => match_listen_to2!(context, config, cfg, TlsTcpListener),
        ListenTo::Quic(cfg) => match_listen_to2!(context, config, cfg, QuicListener),
    }
}

async fn start_server_impl<T: Listener, T2: Listener>(
    context: &Context,
    config: T::Config,
    config2: Option<T2::Config>,
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
    let mut backup_pool = None;
    if let Some(config2) = config2 {
        let listener2 = T2::new(config2).await?;
        let pool2 = TunnelPool::new();
        backup_pool = Some(pool2.clone());
        let listen_to2 = format!("{}", listener2);
        info!("server listening on {}", listener2);
        context.spawn(tunnel_timer(
            context.clone(),
            listener2.to_string(),
            pool2.clone(),
        ));
        context.spawn(
            serve_tunnel(context.children(), listener2, pool2.clone())
                .instrument(error_span!("server_tunnel2", listen_to2)),
        );
    }

    for s in services.iter() {
        match Transport::parse(&s.listen_to)? {
            Transport::Tcp(addr) => {
                let reuse_port = s.reuse_port;
                let listener =
                    PlainTcpListener::new(PlainTcpListenerConfig { addr, reuse_port }).await?;
                let listen_to = format!("{}", listener);
                info!("service starting, listening on {}", listener);
                context.spawn(
                    serve_service(
                        context.children(),
                        listener,
                        s.connect_to.clone(),
                        pool.clone(),
                        backup_pool.clone(),
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
        match context.with_cancel(listener.accept()).await {
            Ok((stream, id)) => {
                pool.clone()
                    .add(context, stream, id)
                    .instrument(info_span!("tunnel", index))
                    .await;
            }
            Err(e) => {
                if e.is_accept_critical() {
                    drop(listener);
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
    context.wait_cancel_and_finish().await;
}

async fn serve_service<T: Listener, U: Listener, V: Listener>(
    context: Context,
    listener: T,
    connect_to: String,
    pool: TunnelPool<U>,
    pool2: Option<TunnelPool<V>>,
) {
    let context = &context;
    let mut index: u64 = 0;
    loop {
        index += 1;
        match context.with_cancel(listener.accept()).await {
            Ok((stream, remote_addr)) => {
                context.spawn(
                    handle_service_stream::<T, U, V>(
                        context.clone(),
                        stream,
                        pool.clone(),
                        pool2.clone(),
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
                    drop(listener);
                    break;
                }
                info!("listener accept error, retrying: {:#}", e);
            }
        }
    }
    context.cancel_all();
    context.wait_cancel_and_finish().await;
}

async fn handle_service_stream<T: Listener, U: Listener, V: Listener>(
    context: Context,
    stream: T::Stream,
    pool: TunnelPool<U>,
    pool2: Option<TunnelPool<V>>,
    connect_to: String,
) {
    match handle_service_stream_impl::<T, U, V>(&context, stream, pool, pool2, &connect_to).await {
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

async fn handle_service_stream_impl<T: Listener, U: Listener, V: Listener>(
    context: &Context,
    stream: T::Stream,
    pool: TunnelPool<U>,
    pool2: Option<TunnelPool<V>>,
    connect_to: &str,
) -> Result<(u64, u64)> {
    debug!("service received a stream");
    if let Some(pool2) = pool2 {
        match pool.try_pop().await {
            Ok((remote, tunnel_addr)) => {
                return handle_service_relay::<T, U>(context, stream, remote, connect_to)
                    .instrument(info_span!("service_relay", tunnel_addr))
                    .await;
            }
            Err(err) => {
                info!("no tunnel found in pool, trying backup pool: {:#}", err);
                match pool2.try_pop().await {
                    Ok((remote, tunnel_addr)) => {
                        return handle_service_relay::<T, V>(context, stream, remote, connect_to)
                            .instrument(info_span!("service_relay", tunnel_addr))
                            .await;
                    }
                    Err(e) => {
                        info!("no tunnel found in backup pool: {:#}", e);
                    }
                }
            }
        }
    }

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
    let r = relay_bidirectional(stream, tunnel).await?;
    Ok(r)
}

struct Session<T: Listener> {
    cancel_tx: oneshot::Sender<()>,
    receiver: oneshot::Receiver<Result<T::Stream>>,
}

impl<T: Listener> Session<T> {
    #[tracing::instrument(skip_all)]
    async fn join(self) -> Result<T::Stream> {
        self.cancel_tx.send(()).unwrap();
        match self.receiver.await {
            Ok(r) => r,
            Err(e) => Err(e.into()),
        }
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
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (sender, receiver) = oneshot::channel();
        let session = Session::<T> {
            cancel_tx,
            receiver,
        };
        self.inner.sessions.lock().await.insert(id.clone(), session);
        self.inner.notify.notify_one();
        let alive_ctx = context.clone();
        context.spawn(async move {
            let r = keep_alive::<T>(alive_ctx, cancel_rx, &id, stream).await;
            match r {
                Ok(_) => match sender.send(r) {
                    Ok(_) => {}
                    Err(_) => unreachable!(),
                },
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
            let r = self.try_pop().await;
            match r {
                Ok(r) => return Ok(r),
                Err(e) => {
                    if e.is_exausted() {
                        self.inner.notify.notified().await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    pub async fn try_pop(&self) -> Result<(T::Stream, String)> {
        let mut sessions = self.inner.sessions.lock().await;
        let result = sessions.pop_first();
        let is_empty = sessions.is_empty();
        drop(sessions);

        match result {
            Some((id, session)) => {
                trace!("match a tunnel: {}", id);
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
                Ok((session, id))
            }
            None => {
                self.inner.requires.fetch_add(1, Ordering::Release);
                Err(Error::exausted())
            }
        }
    }
}

async fn keep_alive<T: Listener>(
    context: Context,
    mut stopped: oneshot::Receiver<()>,
    id: &String,
    mut stream: T::Stream,
) -> Result<T::Stream> {
    let interval = &mut time::interval(Duration::from_secs(5));
    interval.reset();
    let mut message = Message::ping();
    loop {
        tokio::select! {
            _ = &mut stopped => {
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
