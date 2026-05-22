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
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::h3_stream::H3ServerBidiStream;
use crate::http_utils::RequestBody;
use crate::shutdown::ShutdownHandle;

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
  rx: Option<Arc<Mutex<oneshot::Receiver<Result<Box<dyn Io>>>>>>,
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

  /// Create an OnUpgrade for testing purposes.
  #[cfg(test)]
  pub fn new_for_test(
    rx: oneshot::Receiver<Result<Box<dyn Io>>>,
  ) -> Self {
    Self { rx: Some(Arc::new(Mutex::new(rx))) }
  }

  /// Create a linked (trigger, on_upgrade) pair.
  fn pair() -> (UpgradeTrigger, Self) {
    let (tx, rx) = oneshot::channel();
    (
      UpgradeTrigger { sender: tx },
      Self { rx: Some(Arc::new(Mutex::new(rx))) },
    )
  }
}

impl Future for OnUpgrade {
  type Output = Result<Box<dyn Io>>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match &self.rx {
      Some(rx) => {
        Pin::new(&mut *rx.lock().unwrap()).poll(cx).map(|res| {
          match res {
            Ok(inner) => inner,
            Err(_) => Err(anyhow::anyhow!("upgrade canceled")),
          }
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
    self
      .sender
      .send(result)
      .map_err(|_| anyhow::anyhow!("service dropped the upgrade receiver"))
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
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
  ) -> (Self, OnUpgrade) {
    let (trigger, on_upgrade) = OnUpgrade::pair();
    (
      Self { trigger, stream: Some(stream) },
      on_upgrade,
    )
  }

  /// Send H3 success (200 OK) and deliver the stream to the Service.
  pub async fn send_success(
    mut self,
    resp_headers: Option<&http::HeaderMap>,
  ) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send 200 OK response on the H3 stream, preserving upstream headers
    // (e.g. Proxy-Status per RFC 9209).
    let mut builder =
      http::Response::builder().status(http::StatusCode::OK);
    if let Some(headers) = resp_headers {
      if let Some(ref mut hdrs) = builder.headers_mut() {
        hdrs.extend(
          headers.iter().map(|(k, v)| (k.clone(), v.clone())),
        );
      }
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
    let mut builder =
      http::Response::builder().status(status);
    if let Some(headers) = resp_headers {
      if let Some(ref mut hdrs) = builder.headers_mut() {
        hdrs.extend(
          headers.iter().map(|(k, v)| (k.clone(), v.clone())),
        );
      }
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
  req: &mut http::Request<crate::http_utils::RequestBody>,
) -> Option<Pin<Box<dyn Future<Output = Result<Box<dyn Io>>>>>> {
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

/// Shared activity tracker for idle timeout across a bidirectional tunnel.
///
/// Both sides share one tracker. Any successful read or write on either
/// side resets the idle deadline.
#[derive(Clone)]
struct IdleTracker {
  last_active_ms: Arc<AtomicU64>,
  idle_timeout: Duration,
  epoch: tokio::time::Instant,
}

impl IdleTracker {
  fn new(idle_timeout: Duration) -> Self {
    Self {
      last_active_ms: Arc::new(AtomicU64::new(0)),
      idle_timeout,
      epoch: tokio::time::Instant::now(),
    }
  }

  /// Record activity (called on successful read/write).
  fn touch(&self) {
    let ms = self.epoch.elapsed().as_millis() as u64;
    self.last_active_ms.store(ms, Ordering::Relaxed);
  }

  /// Return the instant at which the idle deadline expires based on
  /// the last recorded activity.
  fn deadline(&self) -> tokio::time::Instant {
    let last_ms = self.last_active_ms.load(Ordering::Relaxed);
    let last_instant = self.epoch + Duration::from_millis(last_ms);
    last_instant + self.idle_timeout
  }

  /// Check whether the connection is genuinely idle right now.
  fn is_idle(&self) -> bool {
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
    Self {
      stream,
      tracker,
      idle_check,
    }
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
    // it's a real idle timeout or a stale alarm (the other side may have
    // called touch() which updated last_active_ms but didn't reset our
    // Sleep).  If stale, reset our Sleep to the new deadline.
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
        if buf.filled().len() > 0 {
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
  addr: &str,
) where
  C: AsyncRead + AsyncWrite + Unpin,
  T: AsyncRead + AsyncWrite + Unpin,
{
  if shutdown_handle.is_shutdown() {
    warn!("tunnel to {addr}: shutdown already triggered, aborting");
    return;
  }

  info!("tunnel to {addr}: starting bidirectional transfer");

  let tracker = IdleTracker::new(idle_timeout);
  let client_wrapped = IdleTimeoutStream::new(client, tracker.clone());
  let target_wrapped = IdleTimeoutStream::new(target, tracker);

  // IdleTimeoutStream is !Unpin (contains Sleep), Box::pin to satisfy
  // copy_bidirectional's Unpin requirement.
  let mut client_pinned = Box::pin(client_wrapped);
  let mut target_pinned = Box::pin(target_wrapped);

  let result = tokio::select! {
    res = tokio::io::copy_bidirectional(
      &mut client_pinned,
      &mut target_pinned,
    ) => res,
    _ = shutdown_handle.notified() => {
      warn!("tunnel to {addr}: shutdown by notification");
      return;
    }
  };

  match result {
    Ok((_sent, _received)) => {
      info!("tunnel to {addr}: transfer completed");
    }
    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
      warn!(
        "tunnel to {addr}: idle timeout after {idle_timeout:?}, \
         closing"
      );
    }
    Err(e) => {
      warn!("tunnel to {addr}: transfer error: {e}");
    }
  }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
  use super::*;
  use crate::http_utils::{BytesBufBodyWrapper, RequestBody};
  use http_body_util::Empty;

  #[tokio::test]
  async fn test_on_upgrade_extracts_from_extensions() {
    let (_trigger, upgrade) = OnUpgrade::pair();

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        Empty::<Bytes>::new(),
      )))
      .unwrap();

    req.extensions_mut().insert(upgrade);

    let extracted = OnUpgrade::on(&mut req);
    assert!(
      extracted.is_some(),
      "Should extract OnUpgrade from extensions"
    );

    let second = OnUpgrade::on(&mut req);
    assert!(second.is_none(), "Second extraction should return None");
  }

  #[tokio::test]
  async fn test_on_upgrade_is_available() {
    let (_trigger, upgrade) = OnUpgrade::pair();

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        Empty::<Bytes>::new(),
      )))
      .unwrap();

    assert!(
      !OnUpgrade::is_available(&req),
      "Should not be available before insert"
    );
    req.extensions_mut().insert(upgrade);
    assert!(
      OnUpgrade::is_available(&req),
      "Should be available after insert"
    );
  }

  #[tokio::test]
  async fn test_on_upgrade_resolves_with_error_on_cancel() {
    let (trigger, upgrade) = OnUpgrade::pair();
    drop(trigger); // Drop trigger to cancel

    let result = upgrade.await;
    assert!(
      result.is_err(),
      "Upgrade should resolve with Err on cancel"
    );
  }

  #[tokio::test]
  async fn test_upgrade_trigger_send_success() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client, server_res) = tokio::join!(client_fut, listener.accept());
    let client = client.unwrap();
    let (server, _) = server_res.unwrap();

    let (trigger, upgrade) = OnUpgrade::pair();
    trigger.send(Ok(Box::new(client))).unwrap();

    let result = upgrade.await;
    assert!(result.is_ok(), "Upgrade should resolve with Ok");

    drop(server);
  }

  #[tokio::test]
  async fn test_upgrade_trigger_send_error() {
    let (trigger, upgrade) = OnUpgrade::pair();
    trigger
      .send(Err(anyhow::anyhow!("test error")))
      .unwrap();

    let result = upgrade.await;
    assert!(result.is_err(), "Upgrade should resolve with Err");
  }

  // ============== IdleTracker Tests ==============

  #[test]
  fn test_idle_tracker_new_not_idle() {
    let tracker = IdleTracker::new(Duration::from_secs(30));
    assert!(
      !tracker.is_idle(),
      "Newly created tracker should not be idle"
    );
  }

  #[test]
  fn test_idle_tracker_touch_updates_deadline() {
    let tracker = IdleTracker::new(Duration::from_secs(30));
    let d1 = tracker.deadline();
    // Simulate passage of time by touching after a short sleep
    std::thread::sleep(std::time::Duration::from_millis(50));
    tracker.touch();
    let d2 = tracker.deadline();
    assert!(
      d2 > d1,
      "After touch, deadline should advance: {d2:?} <= {d1:?}"
    );
  }

  #[test]
  fn test_idle_tracker_stale_alarm_not_idle() {
    // Simulate the stale alarm scenario:
    // 1. Tracker created at T+0 with 200ms idle timeout
    // 2. Other side touches at T+150ms (updates last_active_ms)
    // 3. At T+200ms, our local Sleep fires but tracker.is_idle() should
    //    return false because last activity was only 50ms ago.
    let tracker = IdleTracker::new(Duration::from_millis(200));

    // Not idle initially
    assert!(!tracker.is_idle());

    // Simulate other side having activity at T+150ms
    std::thread::sleep(std::time::Duration::from_millis(150));
    tracker.touch();

    // At this point, only ~0ms since last activity → not idle
    assert!(
      !tracker.is_idle(),
      "Should not be idle right after touch"
    );

    // After 250ms total (50ms after touch), still within 200ms timeout
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
      !tracker.is_idle(),
      "50ms after touch should not be idle with 200ms timeout"
    );

    // After 200ms+ since touch → idle
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
      tracker.is_idle(),
      "200ms after touch should be idle with 200ms timeout"
    );
  }

  // ============== run_tunnel Tests ==============

  #[tokio::test]
  async fn test_run_tunnel_idle_timeout_on_no_data() {
    // Two connected TCP streams with no data flowing should time out
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    let shutdown = ShutdownHandle::new();
    let idle_timeout = Duration::from_millis(200);

    let start = std::time::Instant::now();
    run_tunnel(client, server, shutdown, idle_timeout, "test").await;
    let elapsed = start.elapsed();

    assert!(
      elapsed >= Duration::from_millis(150),
      "Should wait for idle timeout, only waited {elapsed:?}"
    );
    assert!(
      elapsed < Duration::from_secs(2),
      "Should not wait much longer than idle timeout, waited {elapsed:?}"
    );
  }

  #[tokio::test]
  async fn test_run_tunnel_no_timeout_with_active_data() {
    // Stream with continuous data should survive past idle_timeout.
    // Use a target that keeps sending data, and a client that drains it.
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // server side: continuously writes data
    let server_handle = tokio::spawn(async move {
      let (mut server, _) = listener.accept().await.unwrap();
      let data = vec![0xABu8; 4096];
      // Send data for longer than idle_timeout (200ms * 10 = 2s)
      for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if server.write_all(&data).await.is_err() {
          break;
        }
      }
      let _ = server.shutdown().await;
    });

    // client side: the tunnel side
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // target: duplex stream to satisfy AsyncRead + AsyncWrite
    let (target, _drain) = tokio::io::duplex(65536);

    // Drain the target's output so writes don't block
    let drainer = tokio::spawn(async move {
      let mut drain = _drain;
      let mut buf = [0u8; 4096];
      loop {
        match drain.read(&mut buf).await {
          Ok(0) => break,
          Ok(_) => continue,
          Err(_) => break,
        }
      }
    });

    let shutdown = ShutdownHandle::new();
    let idle_timeout = Duration::from_millis(200);

    let start = std::time::Instant::now();
    run_tunnel(client, target, shutdown, idle_timeout, "test").await;
    let elapsed = start.elapsed();

    // Tunnel should have survived well past 200ms because data was flowing,
    // and only ended when the server stopped sending and closed.
    assert!(
      elapsed >= Duration::from_millis(500),
      "Tunnel should survive past idle_timeout while data flows, \
       only lasted {elapsed:?}"
    );

    let _ = server_handle.await;
    let _ = drainer.await;
  }

  #[tokio::test]
  async fn test_run_tunnel_completes_on_eof() {
    // When one side closes immediately, tunnel should complete quickly
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    // Server immediately closes
    drop(server);

    let shutdown = ShutdownHandle::new();
    let idle_timeout = Duration::from_secs(60);

    // Use duplex as target (sink doesn't impl AsyncRead)
    let (target, _drain) = tokio::io::duplex(64);
    drop(_drain);

    let start = std::time::Instant::now();
    run_tunnel(client, target, shutdown, idle_timeout, "test").await;
    let elapsed = start.elapsed();

    assert!(
      elapsed < Duration::from_secs(5),
      "Tunnel should complete on EOF, not wait for idle timeout. \
       Elapsed: {elapsed:?}"
    );
  }

  #[tokio::test]
  async fn test_run_tunnel_shutdown_notification() {
    // Tunnel should exit immediately on shutdown notification
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    let shutdown = ShutdownHandle::new();
    let shutdown_clone = shutdown.clone();
    let idle_timeout = Duration::from_secs(60);

    let tunnel_task = tokio::spawn(async move {
      run_tunnel(client, server, shutdown_clone, idle_timeout, "test").await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.shutdown();

    let start = std::time::Instant::now();
    let result = tunnel_task.await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "Tunnel task should complete");
    assert!(
      elapsed < Duration::from_secs(2),
      "Tunnel should exit quickly on shutdown, took {elapsed:?}"
    );
  }

  use tokio::io::{AsyncReadExt, AsyncWriteExt};
}
