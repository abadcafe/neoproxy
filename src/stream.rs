//! Stream types and tunnel logic for bidirectional data transfer.
//!
//! This module provides:
//! - `Io` trait for type-erased streams
//! - `OnUpgrade` and related triggers for SOCKS5/H3 upgrade mechanism
//! - Tunnel functions for bidirectional data transfer

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use hyper_util::rt::TokioIo;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

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
  pub async fn send_success(mut self) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send 200 OK response on the H3 stream
    let resp = http::Response::builder()
      .status(http::StatusCode::OK)
      .body(())
      .unwrap();
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
  ) -> Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send error response on the H3 stream
    let resp =
      http::Response::builder().status(status).body(()).unwrap();
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

/// Default idle timeout for tunnel data transfer (60 seconds).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;

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

/// Run bidirectional copy between client and target streams.
///
/// Handles shutdown notification and idle timeout. Logs the outcome.
pub async fn run_tunnel<C, T>(
  client: &mut C,
  target: &mut T,
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

  let result = tokio::select! {
    res = tokio::time::timeout(
      idle_timeout,
      tokio::io::copy_bidirectional(client, target),
    ) => res,
    _ = shutdown_handle.notified() => {
      warn!("tunnel to {addr}: shutdown by notification");
      return;
    }
  };

  match result {
    Ok(Ok((_sent, _received))) => {
      info!("tunnel to {addr}: transfer completed");
    }
    Ok(Err(e)) => {
      error!("tunnel to {addr}: transfer error: {e}");
    }
    Err(_) => {
      warn!(
        "tunnel to {addr}: idle timeout after {idle_timeout:?}, \
         closing"
      );
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
}
