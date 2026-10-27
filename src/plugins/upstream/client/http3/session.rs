//! module: session
//! responsibility: lease reusable H3 sessions through peer draining
//! public operations: SessionPool::{new, open,
//! close}, SessionLease::attach
//! data entities: SessionPool, State, Activity, ActivityLease,
//! SessionLease, LeasedIo tests: session_tests.rs; http3_tests.rs; H3
//! pool process contracts

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h3::client as h3_cli;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::super::observation::ConnectionObservation;
use super::quic_connect;
use crate::context::RequestContext;
use crate::plugins::upstream::client::protocol::QuicConfig;
use crate::plugins::upstream::config::protocol::PoolConfig;
use crate::plugins::upstream::error::UpstreamError;
use crate::stream::Io;
use crate::tracker::StreamTracker;

struct State {
  connection: Option<quinn::Connection>,
  sender: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  observation: Option<ConnectionObservation>,
}

pub(crate) struct SessionPool {
  state: Rc<tokio::sync::Mutex<State>>,
  activity: Arc<Activity>,
  address: std::net::SocketAddr,
  hostname: Option<String>,
  quic: QuicConfig,
  handshake_timeout: Duration,
  pool: PoolConfig,
  reaper: RefCell<Option<tokio::task::AbortHandle>>,
}

/// h3 closes a connection when its last SendRequest handle drops.
/// Every response/tunnel retains a lease, so evicting a draining cache
/// entry cannot close streams which have already been accepted.
pub(super) struct SessionLease {
  _sender: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  _activity: ActivityLease,
}

struct Activity {
  active: AtomicUsize,
  used: std::sync::Mutex<tokio::time::Instant>,
}
struct ActivityLease(Arc<Activity>);
impl Activity {
  fn is_idle(&self, timeout: Duration) -> bool {
    self.active.load(Ordering::Acquire) == 0
      && self.used.lock().expect("activity lock poisoned").elapsed()
        >= timeout
  }
}
impl ActivityLease {
  fn new(activity: &Arc<Activity>) -> Self {
    activity.active.fetch_add(1, Ordering::AcqRel);
    Self(activity.clone())
  }
}
impl Drop for ActivityLease {
  fn drop(&mut self) {
    *self.0.used.lock().expect("activity lock poisoned") =
      tokio::time::Instant::now();
    self.0.active.fetch_sub(1, Ordering::AcqRel);
  }
}

impl SessionPool {
  pub(crate) fn new(
    address: std::net::SocketAddr,
    hostname: Option<String>,
    quic: QuicConfig,
    handshake_timeout: Duration,
    pool: PoolConfig,
  ) -> Self {
    Self {
      state: Rc::new(tokio::sync::Mutex::new(State {
        connection: None,
        sender: None,
        observation: None,
      })),
      activity: Arc::new(Activity {
        active: AtomicUsize::new(0),
        used: std::sync::Mutex::new(tokio::time::Instant::now()),
      }),
      address,
      hostname,
      quic,
      handshake_timeout,
      pool,
      reaper: RefCell::new(None),
    }
  }

  /// Retire genuinely idle sessions while response leases keep active
  /// streams alive. The task does not keep the pool itself alive.
  fn monitor_idle(
    &self,
    timeout: Duration,
    tracker: &StreamTracker,
  ) -> tokio::task::AbortHandle {
    let state = Rc::downgrade(&self.state);
    let activity = Arc::downgrade(&self.activity);
    let shutdown = tracker.shutdown_handle();
    tracker.register_connection(async move {
      loop {
        tokio::select! {
          () = tokio::time::sleep(timeout) => {},
          () = shutdown.notified() => break,
        }
        let (Some(state), Some(activity)) =
          (state.upgrade(), activity.upgrade())
        else {
          break;
        };
        let mut state = state.lock().await;
        if activity.is_idle(timeout) {
          if let Some(connection) = state.connection.take() {
            connection.close(
              quinn::VarInt::from_u32(0x100),
              b"idle origin pool",
            );
          }
          state.sender = None;
        }
      }
    })
  }

  async fn connection(
    &self,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<
    (
      usize,
      h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
      ConnectionObservation,
    ),
    UpstreamError,
  > {
    if self.pool.max_idle_per_host != 0
      && self.reaper.borrow().is_none()
    {
      let reaper = self.monitor_idle(self.pool.idle_timeout, tracker);
      *self.reaper.borrow_mut() = Some(reaper);
    }
    let mut state = self.state.lock().await;
    if let (Some(connection), Some(sender)) =
      (&state.connection, &state.sender)
      && connection.close_reason().is_none()
    {
      return Ok((
        connection.stable_id(),
        sender.clone(),
        state
          .observation
          .as_ref()
          .expect("connected session observation")
          .clone(),
      ));
    }
    let observation = ConnectionObservation::new();
    state.observation = Some(observation.clone());
    let (connection, sender) =
      establish_http3_connection(self, tls, tracker, &observation)
        .await?;
    let id = connection.stable_id();
    state.connection = Some(connection);
    state.sender = Some(sender.clone());
    Ok((id, sender, observation))
  }

  pub(super) async fn open(
    &self,
    request: http::Request<()>,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<
    (
      h3_cli::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
      SessionLease,
    ),
    UpstreamError,
  > {
    let activity = ActivityLease::new(&self.activity);
    let ctx = request.extensions().get::<RequestContext>().cloned();
    let result = self.checkout(tls, tracker).await;
    if result.is_err()
      && let Some(ctx) = &ctx
      && let Some(observation) = &self.state.lock().await.observation
    {
      observation.record(ctx);
    }
    let (id, mut sender, observation) = result?;
    if let Some(ctx) = &ctx {
      observation.record(ctx);
    }
    super::super::retry_request::Progress::mark_request(&request);
    match sender.send_request(request.clone()).await {
      Ok(stream) => {
        return Ok((
          stream,
          SessionLease { _sender: sender, _activity: activity },
        ));
      }
      Err(h3::error::StreamError::RemoteClosing) => {
        let mut state = self.state.lock().await;
        // Concurrent failures from an old session must not evict the
        // replacement established by another request.
        if state
          .connection
          .as_ref()
          .is_some_and(|connection| connection.stable_id() == id)
        {
          state.connection = None;
          state.sender = None;
        }
      }
      Err(error) => {
        return Err(UpstreamError::ConnectionTerminated(
          error.to_string(),
        ));
      }
    }
    // RemoteClosing is returned before a stream/request is sent. This
    // single retry cannot replay a method or body accepted by a peer.
    let (_, mut sender, observation) =
      self.checkout(tls, tracker).await?;
    if let Some(ctx) = &ctx {
      observation.record(ctx);
    }
    let stream =
      sender.send_request(request).await.map_err(|error| {
        UpstreamError::ConnectionTerminated(error.to_string())
      })?;
    Ok((stream, SessionLease { _sender: sender, _activity: activity }))
  }

  async fn checkout(
    &self,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<
    (
      usize,
      h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
      ConnectionObservation,
    ),
    UpstreamError,
  > {
    let (id, sender, observation) =
      self.connection(tls, tracker).await?;
    if self.pool.max_idle_per_host == 0 {
      // Transfer the session to the exchange lease on every checkout,
      // including a retry after GOAWAY. No idle sender stays cached.
      let mut state = self.state.lock().await;
      if state
        .connection
        .as_ref()
        .is_some_and(|connection| connection.stable_id() == id)
      {
        state.connection = None;
        state.sender = None;
      }
    }
    Ok((id, sender, observation))
  }

  pub(crate) fn close(&self) {
    if let Ok(state) = self.state.try_lock()
      && let Some(connection) = &state.connection
    {
      connection.close(quinn::VarInt::from_u32(0x100), b"shutdown");
    }
  }
}

impl Drop for SessionPool {
  fn drop(&mut self) {
    if let Some(reaper) = self.reaper.get_mut().take() {
      reaper.abort();
    }
  }
}

impl SessionLease {
  pub(super) fn attach<T: Io>(self, transport: T) -> impl Io {
    LeasedIo { inner: transport, _lease: self }
  }
}

struct LeasedIo<T> {
  inner: T,
  _lease: SessionLease,
}
impl<T: AsyncRead + Unpin> AsyncRead for LeasedIo<T> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buffer)
  }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for LeasedIo<T> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buffer)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

async fn establish_http3_connection(
  pool: &SessionPool,
  tls_config: &rustls::ClientConfig,
  tracker: &StreamTracker,
  observation: &ConnectionObservation,
) -> Result<
  (
    quinn::Connection,
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  ),
  UpstreamError,
> {
  let address = &pool.address;
  let quinn_conn =
    create_quic_connection(pool, tls_config, observation).await?;
  let (mut h3_conn, send_request) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone()))
      .await
      .map_err(|e| {
        UpstreamError::ConnectionTerminated(format!(
          "H3 connection setup to {address} failed: {e}"
        ))
      })?;

  tracker.register_connection(async move {
    let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
  });

  Ok((quinn_conn, send_request))
}

async fn create_quic_connection(
  pool: &SessionPool,
  tls_config: &rustls::ClientConfig,
  observation: &ConnectionObservation,
) -> Result<quinn::Connection, UpstreamError> {
  let address = &pool.address;
  let hostname = pool.hostname.as_deref();
  let quic = &pool.quic;
  let tls_handshake_timeout = pool.handshake_timeout;
  let mut tls_config = tls_config.clone();
  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![b"h3".to_vec()];

  let mut cli_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
      .map_err(|e| {
        UpstreamError::TlsProtocolError(format!(
          "QUIC TLS config error: {e}"
        ))
      })?,
  ));

  let mut transport = quinn::TransportConfig::default();
  transport.keep_alive_interval(Some(quic.keep_alive_interval));
  if let Some(idle) = quic.max_idle_timeout {
    let ms = u64::try_from(idle.as_millis()).map_err(|_| {
      UpstreamError::ProxyInternalError(
        "quic max_idle_timeout too large".into(),
      )
    })?;
    transport.max_idle_timeout(Some(
      quinn::VarInt::from_u64(ms)
        .map_err(|_| {
          UpstreamError::ProxyInternalError(
            "quic max_idle_timeout overflow".into(),
          )
        })?
        .into(),
    ));
  }
  if let Some(v) = quic.max_concurrent_bidi_streams {
    transport.max_concurrent_bidi_streams(
      quinn::VarInt::from_u64(v).map_err(|_| {
        UpstreamError::ProxyInternalError(
          "max_concurrent_bidi_streams overflow".into(),
        )
      })?,
    );
  }
  if let Some(v) = quic.initial_mtu {
    transport.initial_mtu(v);
  }
  if let Some(v) = quic.send_window {
    transport.send_window(v);
  }
  if let Some(v) = quic.receive_window {
    transport.receive_window(quinn::VarInt::from_u64(v).map_err(
      |_| {
        UpstreamError::ProxyInternalError(
          "receive_window overflow".into(),
        )
      },
    )?);
  }
  cli_config.transport_config(Arc::new(transport));

  let host = hostname
    .map(str::to_owned)
    .unwrap_or_else(|| address.ip().to_string());
  let tls_started = std::time::Instant::now();
  let result = quic_connect::connect(
    *address,
    &host,
    cli_config,
    tls_handshake_timeout,
  )
  .await;
  observation.tls(tls_started.elapsed());
  let conn = result?;
  observation.endpoint(Some(conn.remote_address()), None);
  Ok(conn)
}
