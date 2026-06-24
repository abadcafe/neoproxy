//! Stream types and tunnel logic for bidirectional data transfer.
//!
//! This module provides:
//! - `Io` trait for type-erased streams
//! - `OnUpgrade` and related triggers for SOCKS5/H3 upgrade mechanism
//! - Tunnel functions for bidirectional data transfer

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::h3_stream::H3ServerBidiStream;
use crate::http_message::RequestBody;
use crate::shutdown::ShutdownHandle;

type UpgradeReceiver =
  Arc<Mutex<oneshot::Receiver<Result<Box<dyn Io>>>>>;
pub type UpgradeFuture =
  Pin<Box<dyn Future<Output = Result<Box<dyn Io>>>>>;

// ============================================================================
// Io trait - for trait objects
// ============================================================================

/// Trait combining AsyncRead + AsyncWrite for trait objects.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Io for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

// ============================================================================
// OnUpgrade - unified upgrade future
// ============================================================================

/// Unified upgrade future for SOCKS5 and H3 listeners.
///
/// Placed into `Request.extensions` by the listener.
/// Service extracts it via `OnUpgrade::on()` and awaits to receive
/// the upgraded stream after the listener sends the protocol response.
#[derive(Clone)]
pub struct OnUpgrade {
  rx: Option<UpgradeReceiver>,
}

impl std::fmt::Debug for OnUpgrade {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("OnUpgrade").finish_non_exhaustive()
  }
}

impl OnUpgrade {
  /// Extract `OnUpgrade` from Request extensions.
  ///
  /// Returns `None` if no upgrade is available.
  pub fn on(req: &mut http::Request<RequestBody>) -> Option<Self> {
    req.extensions_mut().remove::<Self>()
  }

  /// Check if an upgrade is available in the request (test only).
  #[cfg(test)]
  pub fn is_available(req: &http::Request<RequestBody>) -> bool {
    req.extensions().get::<Self>().is_some()
  }

  /// Create a linked (trigger, on_upgrade) pair.
  pub(crate) fn pair() -> (UpgradeTrigger, Self) {
    let (tx, rx) = oneshot::channel();
    (
      UpgradeTrigger { sender: tx },
      Self { rx: Some(Arc::new(Mutex::new(rx))) },
    )
  }
}

impl Future for OnUpgrade {
  type Output = Result<Box<dyn Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    match &self.rx {
      Some(rx) => {
        Pin::new(&mut *rx.lock().unwrap()).poll(cx).map(|res| match res
        {
          Ok(inner) => inner,
          Err(_) => Err(anyhow::anyhow!("upgrade canceled")),
        })
      }
      None => Poll::Ready(Err(anyhow::anyhow!("no upgrade available"))),
    }
  }
}

// ============================================================================
// UpgradeTrigger - generic trigger for listeners
// ============================================================================

/// Trigger for listeners to complete the upgrade.
///
/// Used internally by `H3UpgradeTrigger` and `Socks5UpgradeTrigger`.
pub struct UpgradeTrigger {
  sender: oneshot::Sender<Result<Box<dyn Io>>>,
}

impl UpgradeTrigger {
  /// Send the upgraded stream to the service.
  pub fn send(self, result: Result<Box<dyn Io>>) -> Result<()> {
    self.sender.send(result).map_err(|_| {
      anyhow::anyhow!("service dropped the upgrade receiver")
    })
  }
}

// ============================================================================
// H3UpgradeTrigger - H3-specific trigger
// ============================================================================

/// H3 upgrade trigger (Listener side).
///
/// Held by the H3 listener. After service.call() returns a Response,
/// the listener calls `send_success()` or `send_error()` to:
/// 1. Send the H3 protocol response on the stream
/// 2. Transfer stream ownership to the Service via the upgrade channel
pub struct H3UpgradeTrigger {
  trigger: UpgradeTrigger,
  stream: Option<
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  >,
}

impl std::fmt::Debug for H3UpgradeTrigger {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("H3UpgradeTrigger").finish_non_exhaustive()
  }
}

impl H3UpgradeTrigger {
  /// Create a linked (trigger, on_upgrade) pair.
  pub fn pair(
    stream: h3::server::RequestStream<
      h3_quinn::BidiStream<Bytes>,
      Bytes,
    >,
  ) -> (Self, OnUpgrade) {
    let (trigger, on_upgrade) = OnUpgrade::pair();
    (Self { trigger, stream: Some(stream) }, on_upgrade)
  }

  /// Send H3 success (200 OK) and deliver the stream to the Service.
  pub async fn send_success(
    mut self,
    resp_headers: Option<&http::HeaderMap>,
  ) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send 200 OK response on the H3 stream, preserving upstream
    // headers (e.g. Proxy-Status per RFC 9209).
    let mut builder =
      http::Response::builder().status(http::StatusCode::OK);
    if let Some(headers) = resp_headers
      && let Some(ref mut hdrs) = builder.headers_mut()
    {
      hdrs.extend(headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    let resp = builder.body(()).unwrap();
    stream.send_response(resp).await?;

    // Split into send/recv halves and wrap
    let (send_stream, recv_stream) = stream.split();
    let bidi = H3ServerBidiStream::new(send_stream, recv_stream);

    // Deliver to Service
    self.trigger.send(Ok(Box::new(bidi)))
  }

  /// Send H3 error response and deliver error to the Service.
  pub async fn send_error(
    mut self,
    status: http::StatusCode,
  ) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send error response on the H3 stream
    let resp =
      http::Response::builder().status(status).body(()).unwrap();
    stream.send_response(resp).await?;
    stream.finish().await?;

    // Deliver error to Service
    self
      .trigger
      .send(Err(anyhow::anyhow!("H3 upgrade failed: {}", status)))
  }

  /// Send H3 error response with body and deliver error to the Service.
  pub async fn send_error_with_body(
    mut self,
    status: http::StatusCode,
    body: Bytes,
    resp_headers: Option<&http::HeaderMap>,
  ) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send error response on the H3 stream, preserving upstream
    // headers (e.g. Proxy-Status per RFC 9209).
    let mut builder = http::Response::builder().status(status);
    if let Some(headers) = resp_headers
      && let Some(ref mut hdrs) = builder.headers_mut()
    {
      hdrs.extend(headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    let resp = builder.body(()).unwrap();
    stream.send_response(resp).await?;

    // Send body if not empty
    if !body.is_empty() {
      stream.send_data(body).await?;
    }

    stream.finish().await?;

    // Deliver error to Service
    self
      .trigger
      .send(Err(anyhow::anyhow!("H3 upgrade failed: {}", status)))
  }
}

// ============================================================================
// Socks5UpgradeTrigger - SOCKS5-specific trigger
// ============================================================================

/// SOCKS5 upgrade trigger (Listener side).
///
/// The listener uses this to send the SOCKS5 reply and resolve
/// the Service's `OnUpgrade` future.
pub struct Socks5UpgradeTrigger {
  trigger: UpgradeTrigger,
  proto: Option<
    fast_socks5::server::Socks5ServerProtocol<
      tokio::net::TcpStream,
      fast_socks5::server::states::CommandRead,
    >,
  >,
}

impl std::fmt::Debug for Socks5UpgradeTrigger {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Socks5UpgradeTrigger").finish_non_exhaustive()
  }
}

impl Socks5UpgradeTrigger {
  /// Create a linked (trigger, upgrade) pair.
  pub fn pair(
    proto: fast_socks5::server::Socks5ServerProtocol<
      tokio::net::TcpStream,
      fast_socks5::server::states::CommandRead,
    >,
  ) -> (Self, OnUpgrade) {
    let (trigger, on_upgrade) = OnUpgrade::pair();
    (Self { trigger, proto: Some(proto) }, on_upgrade)
  }

  /// Send SOCKS5 success reply and resolve the upgrade future.
  pub async fn send_success(mut self) -> Result<()> {
    let proto = self.proto.take().expect("proto already consumed");
    let stream = proto
      .reply_success("0.0.0.0:0".parse()?)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;

    self.trigger.send(Ok(Box::new(stream)))
  }

  /// Send SOCKS5 error reply and resolve the upgrade future with error.
  pub async fn send_error(
    mut self,
    error: fast_socks5::ReplyError,
  ) -> Result<()> {
    let proto = self.proto.take().expect("proto already consumed");
    proto
      .reply_error(&error)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;

    self.trigger.send(Err(anyhow::anyhow!("SOCKS5 error: {}", error)))
  }
}

/// Map HTTP status code to SOCKS5 ReplyError.
///
/// Used by the SOCKS5 listener to translate Service response status
/// into appropriate SOCKS5 error codes.
pub fn http_status_to_socks5_error(
  status: http::StatusCode,
) -> fast_socks5::ReplyError {
  match status {
    http::StatusCode::BAD_GATEWAY => {
      fast_socks5::ReplyError::ConnectionRefused
    }
    http::StatusCode::SERVICE_UNAVAILABLE => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    http::StatusCode::GATEWAY_TIMEOUT => {
      fast_socks5::ReplyError::ConnectionTimeout
    }
    http::StatusCode::FORBIDDEN => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    http::StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    _ => fast_socks5::ReplyError::GeneralFailure,
  }
}

// ============================================================================
// Tunnel functions
// ============================================================================

/// Extract an upgrade future from the request.
///
/// Prefers our custom `OnUpgrade` (SOCKS5/H3), falls back to hyper's
/// HTTP upgrade. Returns `None` if no upgrade is available.
pub fn extract_upgrade(
  req: &mut http::Request<crate::http_message::RequestBody>,
) -> Option<UpgradeFuture> {
  if let Some(u) = OnUpgrade::on(req) {
    return Some(Box::pin(u));
  }
  match req.extensions().get::<hyper::upgrade::OnUpgrade>() {
    Some(_) => {
      let http_upgrade = hyper::upgrade::on(req);
      Some(Box::pin(async move {
        let upgraded = http_upgrade.await?;
        Ok(Box::new(TokioIo::new(upgraded)) as Box<dyn Io>)
      }))
    }
    None => None,
  }
}

// ============================================================================
// Shared idle timeout wrapper
// ============================================================================

/// Shared activity tracker for idle timeout across a bidirectional
/// tunnel.
///
/// Both sides share one tracker. Any successful read or write on either
/// side resets the idle deadline.
#[derive(Clone)]
pub(crate) struct IdleTracker {
  last_active_ms: Arc<AtomicU64>,
  idle_timeout: Duration,
  epoch: tokio::time::Instant,
}

impl IdleTracker {
  pub(crate) fn new(idle_timeout: Duration) -> Self {
    Self {
      last_active_ms: Arc::new(AtomicU64::new(0)),
      idle_timeout,
      epoch: tokio::time::Instant::now(),
    }
  }

  /// Record activity (called on successful read/write).
  pub(crate) fn touch(&self) {
    let ms = self.epoch.elapsed().as_millis() as u64;
    self.last_active_ms.store(ms, Ordering::Relaxed);
  }

  /// Return the instant at which the idle deadline expires based on
  /// the last recorded activity.
  pub(crate) fn deadline(&self) -> tokio::time::Instant {
    let last_ms = self.last_active_ms.load(Ordering::Relaxed);
    let last_instant = self.epoch + Duration::from_millis(last_ms);
    last_instant + self.idle_timeout
  }

  /// Check whether the connection is genuinely idle right now.
  pub(crate) fn is_idle(&self) -> bool {
    let now_ms = self.epoch.elapsed().as_millis() as u64;
    let last = self.last_active_ms.load(Ordering::Relaxed);
    now_ms.saturating_sub(last) > self.idle_timeout.as_millis() as u64
  }
}

pin_project_lite::pin_project! {
  /// AsyncRead + AsyncWrite wrapper with shared idle timeout.
  ///
  /// On each successful read/write, the shared `IdleTracker` is updated.
  /// An internal `Sleep` fires at the current idle deadline; when it
  /// expires (no activity for `idle_timeout`), the next I/O poll
  /// returns `TimedOut`.
  struct IdleTimeoutStream<S> {
    #[pin]
    stream: S,
    tracker: IdleTracker,
    #[pin]
    idle_check: tokio::time::Sleep,
  }
}

impl<S> IdleTimeoutStream<S> {
  fn new(stream: S, tracker: IdleTracker) -> Self {
    let idle_check = tokio::time::sleep_until(tracker.deadline());
    Self { stream, tracker, idle_check }
  }
}

impl<S: AsyncRead> AsyncRead for IdleTimeoutStream<S> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let mut this = self.project();

    // If our local Sleep has fired, check the shared tracker to see if
    // it's a real idle timeout or a stale alarm (the other side may
    // have called touch() which updated last_active_ms but didn't
    // reset our Sleep).  If stale, reset our Sleep to the new
    // deadline.
    if this.idle_check.as_mut().poll(cx).is_ready() {
      if this.tracker.is_idle() {
        return Poll::Ready(Err(std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "idle timeout",
        )));
      }
      // Stale alarm — the other side was active. Reset our Sleep.
      this.idle_check.as_mut().reset(this.tracker.deadline());
    }

    match this.stream.poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        if !buf.filled().is_empty() {
          this.tracker.touch();
          this.idle_check.as_mut().reset(this.tracker.deadline());
        }
        Poll::Ready(Ok(()))
      }
      other => other,
    }
  }
}

impl<S: AsyncWrite> AsyncWrite for IdleTimeoutStream<S> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let mut this = self.project();

    if this.idle_check.as_mut().poll(cx).is_ready() {
      if this.tracker.is_idle() {
        return Poll::Ready(Err(std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "idle timeout",
        )));
      }
      this.idle_check.as_mut().reset(this.tracker.deadline());
    }

    match this.stream.poll_write(cx, buf) {
      Poll::Ready(Ok(n)) => {
        if n > 0 {
          this.tracker.touch();
          this.idle_check.as_mut().reset(this.tracker.deadline());
        }
        Poll::Ready(Ok(n))
      }
      other => other,
    }
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.project().stream.poll_flush(cx)
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    self.project().stream.poll_shutdown(cx)
  }
}

// ============================================================================
// TaggedIo - tags I/O errors with a side label
// ============================================================================

/// Wrapper that injects a side tag (e.g. "client", "upstream") into I/O
/// errors, so that `copy_bidirectional` error messages indicate which
/// side failed.
struct TaggedIo<S> {
  inner: S,
  tag: &'static str,
}

impl<S> TaggedIo<S> {
  fn new(inner: S, tag: &'static str) -> Self {
    Self { inner, tag }
  }
}

impl<S: AsyncRead + Unpin> AsyncRead for TaggedIo<S> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_read(cx, buf) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        format!("[{}] {}", self.tag, e),
      ))),
      other => other,
    }
  }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TaggedIo<S> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    match Pin::new(&mut self.inner).poll_write(cx, buf) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        format!("[{}] {}", self.tag, e),
      ))),
      other => other,
    }
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_flush(cx) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        format!("[{}] {}", self.tag, e),
      ))),
      other => other,
    }
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<std::io::Result<()>> {
    match Pin::new(&mut self.inner).poll_shutdown(cx) {
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
        e.kind(),
        format!("[{}] {}", self.tag, e),
      ))),
      other => other,
    }
  }
}

// ============================================================================
// Tunnel functions
// ============================================================================

/// Run bidirectional copy between client and target streams.
///
/// Handles shutdown notification and idle timeout. Logs the outcome.
/// Idle timeout is shared across both directions: if data flows in
/// EITHER direction, the connection is considered active.
pub async fn run_tunnel<C, T>(
  client: C,
  target: T,
  shutdown_handle: ShutdownHandle,
  idle_timeout: Duration,
  tunnel_desc: &str,
) where
  C: AsyncRead + AsyncWrite + Unpin,
  T: AsyncRead + AsyncWrite + Unpin,
{
  if shutdown_handle.is_shutdown() {
    warn!("tunnel {tunnel_desc}: shutdown already triggered, aborting");
    return;
  }

  info!("tunnel {tunnel_desc}: bidirectional transfer started");

  let tracker = IdleTracker::new(idle_timeout);
  let client_wrapped = IdleTimeoutStream::new(client, tracker.clone());
  let target_wrapped = IdleTimeoutStream::new(target, tracker);

  let client_tagged = TaggedIo::new(Box::pin(client_wrapped), "client");
  let target_tagged =
    TaggedIo::new(Box::pin(target_wrapped), "upstream");

  let mut client_pinned = client_tagged;
  let mut target_pinned = target_tagged;

  let result = tokio::select! {
    res = tokio::io::copy_bidirectional(
      &mut client_pinned,
      &mut target_pinned,
    ) => res,
    _ = shutdown_handle.notified() => {
      warn!("tunnel {tunnel_desc}: shutdown by notification");
      return;
    }
  };

  match result {
    Ok((_sent, _received)) => {
      info!("tunnel {tunnel_desc}: transfer completed");
    }
    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
      warn!(
        "tunnel {tunnel_desc}: idle timeout after {idle_timeout:?}, \
         closing"
      );
    }
    Err(e) => {
      warn!("tunnel {tunnel_desc}: transfer error: {e}");
    }
  }
}
