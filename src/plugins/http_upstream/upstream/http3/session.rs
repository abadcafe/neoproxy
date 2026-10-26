//! module: session
//! responsibility: lease reusable H3 sessions through peer draining
//! public operations: SessionPool::{new, open, close},
//! SessionLease::attach data entities: SessionPool, State,
//! SessionLease, LeasedIo tests: http3_tests.rs through Http3Client's
//! public transport contract

use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use h3::client as h3_cli;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::info;

use super::quic_connect;
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_quic_error,
};
use crate::plugins::http_upstream::upstream::address_resolution::resolve_addresses;
use crate::plugins::http_upstream::upstream::protocol::QuicConfig;
use crate::stream::Io;
use crate::tracker::StreamTracker;

struct State {
  connection: Option<quinn::Connection>,
  sender: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

pub(crate) struct SessionPool {
  state: Rc<tokio::sync::Mutex<State>>,
  activity: Arc<Activity>,
  address: String,
  hostname: Option<String>,
  quic: QuicConfig,
  handshake_timeout: Duration,
  dns_timeout: Duration,
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
  /// Prepare QUIC and H3 before a request can be committed to this
  /// peer.
  pub(crate) async fn prepare(
    &self,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<(), UpstreamError> {
    let _activity = ActivityLease::new(&self.activity);
    self.connection(tls, tracker).await.map(|_| ())
  }

  pub(crate) fn new(
    address: String,
    hostname: Option<String>,
    quic: QuicConfig,
    handshake_timeout: Duration,
    dns_timeout: Duration,
  ) -> Self {
    Self {
      state: Rc::new(tokio::sync::Mutex::new(State {
        connection: None,
        sender: None,
      })),
      activity: Arc::new(Activity {
        active: AtomicUsize::new(0),
        used: std::sync::Mutex::new(tokio::time::Instant::now()),
      }),
      address,
      hostname,
      quic,
      handshake_timeout,
      dns_timeout,
    }
  }

  /// Retire genuinely idle sessions while response leases keep active
  /// streams alive. The task does not keep the pool itself alive.
  pub(crate) fn monitor_idle(
    &self,
    timeout: Duration,
    tracker: &StreamTracker,
  ) {
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
        if activity.active.load(Ordering::Acquire) == 0
          && activity
            .used
            .lock()
            .expect("activity lock poisoned")
            .elapsed()
            >= timeout
        {
          if let Some(connection) = state.connection.take() {
            connection.close(
              quinn::VarInt::from_u32(0x100),
              b"idle origin pool",
            );
          }
          state.sender = None;
        }
      }
    });
  }

  async fn connection(
    &self,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<
    (usize, h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>),
    UpstreamError,
  > {
    let mut state = self.state.lock().await;
    if let (Some(connection), Some(sender)) =
      (&state.connection, &state.sender)
      && connection.close_reason().is_none()
    {
      return Ok((connection.stable_id(), sender.clone()));
    }
    let (connection, sender) = establish_http3_connection(
      &self.address,
      self.hostname.as_deref(),
      &self.quic,
      self.handshake_timeout,
      self.dns_timeout,
      tls,
      tracker,
    )
    .await?;
    let id = connection.stable_id();
    state.connection = Some(connection);
    state.sender = Some(sender.clone());
    Ok((id, sender))
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
    let (id, mut sender) = self.connection(tls, tracker).await?;
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
    let (_, mut sender) = self.connection(tls, tracker).await?;
    let stream =
      sender.send_request(request).await.map_err(|error| {
        UpstreamError::ConnectionTerminated(error.to_string())
      })?;
    Ok((stream, SessionLease { _sender: sender, _activity: activity }))
  }

  pub(crate) fn close(&self) {
    if let Ok(state) = self.state.try_lock()
      && let Some(connection) = &state.connection
    {
      connection.close(quinn::VarInt::from_u32(0x100), b"shutdown");
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
  address: &str,
  hostname: Option<&str>,
  quic: &QuicConfig,
  tls_handshake_timeout: Duration,
  dns_timeout: Duration,
  tls_config: &rustls::ClientConfig,
  tracker: &Rc<StreamTracker>,
) -> Result<
  (
    quinn::Connection,
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  ),
  UpstreamError,
> {
  let quinn_conn = create_quic_connection(
    address,
    hostname,
    quic,
    tls_config,
    tls_handshake_timeout,
    dns_timeout,
  )
  .await?;

  let (mut h3_conn, send_request) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone()))
      .await
      .map_err(|e| {
        UpstreamError::ProxyInternalError(format!(
          "H3 connection setup to {address} failed: {e}"
        ))
      })?;

  tracker.register_connection(async move {
    let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
  });

  info!("HTTP/3 connection established to {address}");
  Ok((quinn_conn, send_request))
}

async fn create_quic_connection(
  address: &str,
  hostname: Option<&str>,
  quic: &QuicConfig,
  tls_config: &rustls::ClientConfig,
  tls_handshake_timeout: Duration,
  dns_timeout: Duration,
) -> Result<quinn::Connection, UpstreamError> {
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

  let addresses =
    tokio::time::timeout(dns_timeout, resolve_addresses(address))
      .await
      .map_err(|_| {
        UpstreamError::DnsError(format!(
          "DNS resolve for '{address}' timed out"
        ))
      })?
      .map_err(classify_quic_error)?;
  let host: &str = hostname.unwrap_or_else(|| {
    address.split_at(address.rfind(':').unwrap_or(address.len())).0
  });
  let host = host.trim_start_matches('[').trim_end_matches(']');
  let conn = quic_connect::connect(
    addresses,
    host,
    cli_config,
    tls_handshake_timeout,
  )
  .await?;

  info!("QUIC connection established to {address}");
  Ok(conn)
}
