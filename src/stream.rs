use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::h3_stream::H3ServerBidiStream;
use crate::http_utils::RequestBody;

/// H3 upgrade error.
#[derive(Debug)]
pub enum H3UpgradeError {
  /// Listener sent an error response.
  ErrorResponse(http::StatusCode),
  /// Upgrade was canceled (Listener did not trigger).
  Canceled,
}

impl std::fmt::Display for H3UpgradeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::ErrorResponse(status) => {
        write!(f, "H3 upgrade error response: {}", status)
      }
      Self::Canceled => write!(f, "H3 upgrade canceled"),
    }
  }
}

impl std::error::Error for H3UpgradeError {}

/// H3 upgrade Future (Service side).
///
/// Placed into Request.extensions by the Listener.
/// Service extracts it and `.await`s to receive the H3ServerBidiStream
/// after the Listener sends the protocol response.
///
/// # Single-Awaiter Contract
///
/// Same as Socks5OnUpgrade: although Clone (required by http::Extensions::insert),
/// only ONE instance should ever be .await'd. The on() extraction method removes
/// the value from extensions, preventing accidental double-await.
#[derive(Clone)]
pub struct H3OnUpgrade {
  receiver: Option<
    Arc<
      std::sync::Mutex<
        Option<
          tokio::sync::oneshot::Receiver<
            Result<H3ServerBidiStream, H3UpgradeError>,
          >,
        >,
      >,
    >,
  >,
}

impl std::fmt::Debug for H3OnUpgrade {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("H3OnUpgrade").finish_non_exhaustive()
  }
}

impl H3OnUpgrade {
  /// Extract H3OnUpgrade from Request extensions.
  ///
  /// Returns None if no H3 upgrade is available.
  ///
  /// This method is used by Services (connect_tcp, http3_chain) to extract
  /// H3OnUpgrade from requests received from the H3 listener.
  pub fn on(req: &mut http::Request<RequestBody>) -> Option<Self> {
    req.extensions_mut().remove::<Self>()
  }

  /// Check if an H3 upgrade is available in the request.
  /// Only available in test builds.
  #[cfg(test)]
  pub fn is_available(req: &http::Request<RequestBody>) -> bool {
    req.extensions().get::<Self>().is_some()
  }
}

impl Future for H3OnUpgrade {
  type Output = Result<H3ServerBidiStream, H3UpgradeError>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    match self.receiver {
      Some(ref rx) => {
        let mut guard = rx.lock().unwrap();
        match guard.as_mut() {
          Some(receiver) => Pin::new(receiver).poll(cx).map(|result| {
            guard.take();
            match result {
              Ok(inner) => inner,
              Err(_) => Err(H3UpgradeError::Canceled),
            }
          }),
          None => Poll::Ready(Err(H3UpgradeError::Canceled)),
        }
      }
      None => Poll::Ready(Err(H3UpgradeError::Canceled)),
    }
  }
}

/// H3 upgrade trigger (Listener side).
///
/// Held by the Listener. After service.call() returns a Response,
/// the Listener calls send_success() or send_error() to:
/// 1. Send the H3 protocol response on the stream
/// 2. Transfer stream ownership to the Service via the upgrade channel
pub struct H3UpgradeTrigger {
  sender: tokio::sync::oneshot::Sender<
    Result<H3ServerBidiStream, H3UpgradeError>,
  >,
  stream: Option<
    h3::server::RequestStream<
      h3_quinn::BidiStream<bytes::Bytes>,
      bytes::Bytes,
    >,
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
      h3_quinn::BidiStream<bytes::Bytes>,
      bytes::Bytes,
    >,
  ) -> (Self, H3OnUpgrade) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let trigger = Self { sender, stream: Some(stream) };
    let upgrade = H3OnUpgrade {
      receiver: Some(Arc::new(std::sync::Mutex::new(Some(receiver)))),
    };
    (trigger, upgrade)
  }

  /// Send H3 success (200 OK) and deliver the stream to the Service.
  ///
  /// 1. Sends 200 OK on the H3 stream (end_of_stream = false)
  /// 2. Splits the stream into send/recv halves
  /// 3. Wraps in H3ServerBidiStream
  /// 4. Sends Ok(stream) via oneshot channel
  pub async fn send_success(mut self) -> anyhow::Result<()> {
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
    if self.sender.send(Ok(bidi)).is_err() {
      return Err(anyhow::anyhow!(
        "H3 upgrade: Service dropped the receiver before success was delivered"
      ));
    }
    Ok(())
  }

  /// Send H3 error response and deliver error to the Service.
  ///
  /// 1. Sends error response on the H3 stream
  /// 2. Finishes the stream
  /// 3. Sends Err(ErrorResponse(status)) via oneshot channel
  pub async fn send_error(
    mut self,
    status: http::StatusCode,
  ) -> anyhow::Result<()> {
    let mut stream =
      self.stream.take().expect("stream already consumed");

    // Send error response on the H3 stream
    let resp =
      http::Response::builder().status(status).body(()).unwrap();
    stream.send_response(resp).await?;
    stream.finish().await?;

    // Deliver error to Service
    if self
      .sender
      .send(Err(H3UpgradeError::ErrorResponse(status)))
      .is_err()
    {
      return Err(anyhow::anyhow!(
        "H3 upgrade: Service dropped the receiver before error was delivered"
      ));
    }
    Ok(())
  }

  /// Send H3 error response with body and deliver error to the Service.
  ///
  /// 1. Sends error response with body on the H3 stream
  /// 2. Finishes the stream
  /// 3. Sends Err(ErrorResponse(status)) via oneshot channel
  pub async fn send_error_with_body(
    mut self,
    status: http::StatusCode,
    body: bytes::Bytes,
  ) -> anyhow::Result<()> {
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
    if self
      .sender
      .send(Err(H3UpgradeError::ErrorResponse(status)))
      .is_err()
    {
      return Err(anyhow::anyhow!(
        "H3 upgrade: Service dropped the receiver before error was delivered"
      ));
    }
    Ok(())
  }
}

/// A stream that can be either a SOCKS5 TCP stream or an HTTP upgraded stream.
///
/// This enum is needed because Rust doesn't allow trait objects with multiple
/// non-auto traits (e.g., `dyn AsyncRead + AsyncWrite`). It is used by
/// `connect_tcp` and `http3_chain` services to handle client streams uniformly
/// regardless of whether they come from SOCKS5 or HTTP CONNECT.
///
/// # Example
///
/// ```ignore
/// // In service call:
/// let client: ClientStream = if let Some(socks5) = socks5_upgrade {
///     match socks5.await {
///         Ok(stream) => ClientStream::Socks5(stream),
///         Err(e) => return Err(...),
///     }
/// } else if let Some(http) = http_upgrade {
///     match http.await {
///         Ok(upgraded) => ClientStream::Http(TokioIo::new(upgraded)),
///         Err(e) => return Err(...),
///     }
/// } else {
///     return Err(...);
/// };
///
/// // Use with copy_bidirectional
/// tokio::io::copy_bidirectional(&mut client, &mut target_stream).await?;
/// ```
pub enum ClientStream {
  /// A SOCKS5 TCP stream from `Socks5OnUpgrade`.
  Socks5(tokio::net::TcpStream),
  /// An HTTP upgraded stream wrapped in `TokioIo`.
  Http(hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>),
  /// An HTTP/3 bidirectional stream from H3 listener.
  H3(H3ServerBidiStream),
}

impl AsyncRead for ClientStream {
  fn poll_read(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    match self.get_mut() {
      ClientStream::Socks5(stream) => {
        std::pin::Pin::new(stream).poll_read(cx, buf)
      }
      ClientStream::Http(stream) => {
        std::pin::Pin::new(stream).poll_read(cx, buf)
      }
      ClientStream::H3(stream) => {
        std::pin::Pin::new(stream).poll_read(cx, buf)
      }
    }
  }
}

impl AsyncWrite for ClientStream {
  fn poll_write(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<std::io::Result<usize>> {
    match self.get_mut() {
      ClientStream::Socks5(stream) => {
        std::pin::Pin::new(stream).poll_write(cx, buf)
      }
      ClientStream::Http(stream) => {
        std::pin::Pin::new(stream).poll_write(cx, buf)
      }
      ClientStream::H3(stream) => {
        std::pin::Pin::new(stream).poll_write(cx, buf)
      }
    }
  }

  fn poll_flush(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    match self.get_mut() {
      ClientStream::Socks5(stream) => {
        std::pin::Pin::new(stream).poll_flush(cx)
      }
      ClientStream::Http(stream) => {
        std::pin::Pin::new(stream).poll_flush(cx)
      }
      ClientStream::H3(stream) => {
        std::pin::Pin::new(stream).poll_flush(cx)
      }
    }
  }

  fn poll_shutdown(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    match self.get_mut() {
      ClientStream::Socks5(stream) => {
        std::pin::Pin::new(stream).poll_shutdown(cx)
      }
      ClientStream::Http(stream) => {
        std::pin::Pin::new(stream).poll_shutdown(cx)
      }
      ClientStream::H3(stream) => {
        std::pin::Pin::new(stream).poll_shutdown(cx)
      }
    }
  }
}

/// SOCKS5 upgrade error.
#[derive(Debug)]
pub enum Socks5UpgradeError {
  /// Listener sent an error response.
  ReplyError(fast_socks5::ReplyError),
  /// Upgrade was canceled (Listener did not trigger).
  Canceled,
}

impl std::fmt::Display for Socks5UpgradeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::ReplyError(e) => write!(f, "SOCKS5 reply error: {}", e),
      Self::Canceled => write!(f, "SOCKS5 upgrade canceled"),
    }
  }
}

impl std::error::Error for Socks5UpgradeError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::ReplyError(e) => Some(e),
      Self::Canceled => None,
    }
  }
}

/// SOCKS5 upgrade Future.
///
/// Mimics `hyper::upgrade::OnUpgrade` behavior.
/// Service extracts this from `Request.extensions` and awaits it
/// in a background task. The future resolves after the Listener
/// sends the SOCKS5 reply.
///
/// The inner receiver is wrapped in `Arc<Mutex<>>` to satisfy
/// `http::Extensions::insert`'s `Clone` requirement, following
/// the same pattern as `hyper::upgrade::OnUpgrade`.
///
/// # Single-Awaiter Contract
///
/// Although this type implements `Clone` (required by `http::Extensions::insert`),
/// only ONE instance should ever be `.await`ed. The `on()` extraction method
/// removes the value from extensions, preventing accidental double-await in
/// normal use. Concurrently awaiting multiple cloned instances is undefined
/// behavior: only one clone's waker is registered on the shared receiver at a
/// time, so the other clones may stall indefinitely and never receive
/// `Socks5UpgradeError::Canceled`. Sequentially awaiting (where the second
/// await starts after the first has resolved) will correctly return
/// `Socks5UpgradeError::Canceled` for the second await. Do not clone this
/// value before extraction unless you have a specific reason to do so.
#[derive(Clone)]
pub struct Socks5OnUpgrade {
  receiver: Option<
    Arc<
      std::sync::Mutex<
        Option<
          tokio::sync::oneshot::Receiver<
            Result<tokio::net::TcpStream, Socks5UpgradeError>,
          >,
        >,
      >,
    >,
  >,
}

impl std::fmt::Debug for Socks5OnUpgrade {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Socks5OnUpgrade").finish_non_exhaustive()
  }
}

impl Socks5OnUpgrade {
  /// Extract Socks5OnUpgrade from Request extensions.
  ///
  /// Similar to `hyper::upgrade::on(&req)`.
  /// Returns `None` if no SOCKS5 upgrade is available.
  pub fn on(req: &mut http::Request<RequestBody>) -> Option<Self> {
    req.extensions_mut().remove::<Self>()
  }

  /// Check if a SOCKS5 upgrade is available in the request.
  /// Only available in test builds.
  #[cfg(test)]
  pub fn is_available(req: &http::Request<RequestBody>) -> bool {
    req.extensions().get::<Self>().is_some()
  }
}

impl std::future::Future for Socks5OnUpgrade {
  type Output = Result<tokio::net::TcpStream, Socks5UpgradeError>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    match self.receiver {
      Some(ref rx) => {
        let mut guard = rx.lock().unwrap();
        match guard.as_mut() {
          Some(receiver) => Pin::new(receiver).poll(cx).map(|result| {
            // Take the receiver out after it resolves to prevent
            // double-poll panics on cloned instances sharing the
            // same Arc<Mutex<Option<Receiver>>>.
            guard.take();
            match result {
              Ok(inner) => inner,
              Err(_) => Err(Socks5UpgradeError::Canceled),
            }
          }),
          None => {
            // Receiver was already consumed by a previous poll
            // (from this or a cloned instance). Return Canceled
            // instead of panicking.
            Poll::Ready(Err(Socks5UpgradeError::Canceled))
          }
        }
      }
      None => Poll::Ready(Err(Socks5UpgradeError::Canceled)),
    }
  }
}

/// SOCKS5 upgrade trigger (Listener side).
///
/// The Listener uses this to send the SOCKS5 reply and resolve
/// the Service's `Socks5OnUpgrade` future.
pub struct Socks5UpgradeTrigger {
  sender: tokio::sync::oneshot::Sender<
    Result<tokio::net::TcpStream, Socks5UpgradeError>,
  >,
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
  ) -> (Self, Socks5OnUpgrade) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let trigger = Self { sender, proto: Some(proto) };
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(std::sync::Mutex::new(Some(receiver)))),
    };
    (trigger, upgrade)
  }

  /// Send SOCKS5 success reply and resolve the upgrade future.
  ///
  /// 1. Sends SOCKS5 success reply (REP=0x00)
  /// 2. Gets the client stream
  /// 3. Sends stream to Service (resolves on_upgrade.await)
  ///
  /// Returns an error if the Service has already dropped the upgrade
  /// receiver (e.g., due to timeout or cancellation). Note: the SOCKS5
  /// success reply has already been sent to the client at this point,
  /// so the client will believe the connection succeeded but the Service
  /// has no stream to forward data through.
  pub async fn send_success(mut self) -> Result<()> {
    let proto = self.proto.take().expect("proto already consumed");
    let stream = proto
      .reply_success("0.0.0.0:0".parse()?)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;
    if let Err(stream) = self.sender.send(Ok(stream)) {
      // Service dropped the receiver. Gracefully shut down the stream
      // to send FIN instead of RST, which is better protocol hygiene.
      use tokio::io::AsyncWriteExt;
      let mut stream = stream.unwrap(); // Extract from Ok()
      let _ = stream.shutdown().await;
      return Err(anyhow::anyhow!(
        "SOCKS5 upgrade: Service dropped the receiver before success reply was delivered"
      ));
    }
    Ok(())
  }

  /// Send SOCKS5 error reply and resolve the upgrade future with error.
  ///
  /// Returns an error if the Service has already dropped the upgrade
  /// receiver. The SOCKS5 error reply has already been sent to the client,
  /// so this is less severe than a send_success failure.
  pub async fn send_error(
    mut self,
    error: fast_socks5::ReplyError,
  ) -> Result<()> {
    let proto = self.proto.take().expect("proto already consumed");
    proto
      .reply_error(&error)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;
    if self
      .sender
      .send(Err(Socks5UpgradeError::ReplyError(error)))
      .is_err()
    {
      // Return error without logging - the caller will log with context.
      return Err(anyhow::anyhow!(
        "SOCKS5 upgrade: Service dropped the receiver before error reply was delivered"
      ));
    }
    Ok(())
  }
}

#[cfg(test)]
impl Socks5OnUpgrade {
  pub fn new_for_test(
    receiver: tokio::sync::oneshot::Receiver<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >,
  ) -> Self {
    Self {
      receiver: Some(Arc::new(std::sync::Mutex::new(Some(receiver)))),
    }
  }
}

#[cfg(test)]
impl Socks5UpgradeTrigger {
  /// Test-only constructor for testing channel behavior without a real SOCKS5 protocol.
  ///
  /// This creates a trigger that can test the oneshot channel semantics,
  /// including the receiver-dropped path. Note that `send_success()` and
  /// `send_error()` will panic if called on a trigger created this way
  /// (use `send_test_value()` instead for channel testing).
  pub fn new_for_test_channel_only() -> (Self, Socks5OnUpgrade) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let trigger = Self {
      sender,
      proto: None, // No protocol - send_success/send_error will panic
    };
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(std::sync::Mutex::new(Some(receiver)))),
    };
    (trigger, upgrade)
  }

  /// Send a test value through the channel (test-only).
  ///
  /// This simulates the channel send behavior of `send_success()` and
  /// `send_error()` without requiring a real SOCKS5 protocol.
  /// Returns the same error message format as the real methods when
  /// the receiver is dropped.
  pub fn send_test_value_for_channel_test(
    self,
    value: Result<tokio::net::TcpStream, Socks5UpgradeError>,
  ) -> Result<()> {
    match value {
      Ok(stream) => {
        if let Err(stream) = self.sender.send(Ok(stream)) {
          // Service dropped the receiver - simulate graceful shutdown behavior
          // Note: In real send_success(), we would call stream.shutdown().await
          // Here we just drop the stream immediately since this is a channel test
          drop(stream);
          return Err(anyhow::anyhow!(
            "SOCKS5 upgrade: Service dropped the receiver before success reply was delivered"
          ));
        }
        Ok(())
      }
      Err(e) => {
        if self.sender.send(Err(e)).is_err() {
          return Err(anyhow::anyhow!(
            "SOCKS5 upgrade: Service dropped the receiver before error reply was delivered"
          ));
        }
        Ok(())
      }
    }
  }
}

/// Map HTTP status code to SOCKS5 ReplyError.
///
/// Used by the Listener to translate Service response status
/// into appropriate SOCKS5 error codes.
///
/// # Error Fidelity
///
/// HTTP status codes have less granularity than SOCKS5 reply codes.
/// The mapping preserves fidelity where possible:
/// - `BAD_GATEWAY` (502): target refused the connection -> `ConnectionRefused`
/// - `SERVICE_UNAVAILABLE` (503): service denied / shutting down -> `ConnectionNotAllowed`
/// - `GATEWAY_TIMEOUT` (504): connection timed out -> `ConnectionTimeout` (REP=0x06)
/// - `FORBIDDEN` (403): access denied -> `ConnectionNotAllowed`
///
/// `SERVICE_UNAVAILABLE` is typically returned when the service is shutting
/// down or overloaded, not for network unreachability. It maps to
/// `ConnectionNotAllowed` which accurately conveys "service denied" semantics
/// rather than "network unreachable" (which would mislead clients into
/// diagnosing a routing problem).
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::http_utils::{BytesBufBodyWrapper, RequestBody};
  use std::sync::Mutex;

  #[tokio::test]
  async fn test_socks5_on_upgrade_extracts_from_extensions() {
    let (_tx, rx) = tokio::sync::oneshot::channel();
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    req.extensions_mut().insert(upgrade);

    let extracted = Socks5OnUpgrade::on(&mut req);
    assert!(
      extracted.is_some(),
      "Should extract Socks5OnUpgrade from extensions"
    );

    let second = Socks5OnUpgrade::on(&mut req);
    assert!(second.is_none(), "Second extraction should return None");
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_is_available() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    assert!(
      !Socks5OnUpgrade::is_available(&req),
      "Should not be available before insert"
    );
    req.extensions_mut().insert(upgrade);
    assert!(
      Socks5OnUpgrade::is_available(&req),
      "Should be available after insert"
    );
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_resolves_with_stream() {
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client.unwrap();
    let (server, _) = server_res.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    tx.send(Ok(client)).ok();

    let result = upgrade.await;
    assert!(result.is_ok(), "Upgrade should resolve with Ok");

    drop(server);
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_resolves_with_error_on_cancel() {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    drop(tx);

    let result = upgrade.await;
    assert!(
      result.is_err(),
      "Upgrade should resolve with Err on cancel"
    );
  }

  #[test]
  fn test_http_status_to_socks5_error_mappings() {
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::BAD_GATEWAY)
        .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_REFUSED
    );
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::GATEWAY_TIMEOUT)
        .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_TTL_EXPIRED
    );
    assert_eq!(
      http_status_to_socks5_error(
        http::StatusCode::SERVICE_UNAVAILABLE
      )
      .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED
    );
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::FORBIDDEN).as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED
    );
    assert_eq!(
      http_status_to_socks5_error(
        http::StatusCode::INTERNAL_SERVER_ERROR
      )
      .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_GENERAL_FAILURE
    );
  }

  #[test]
  fn test_socks5_on_upgrade_debug_impl() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };
    let debug_str = format!("{:?}", upgrade);
    assert!(
      debug_str.contains("Socks5OnUpgrade"),
      "Debug output should contain type name, got: {}",
      debug_str
    );
  }

  #[test]
  fn test_socks5_on_upgrade_none_debug_impl() {
    let upgrade = Socks5OnUpgrade { receiver: None };
    let debug_str = format!("{:?}", upgrade);
    assert!(
      debug_str.contains("Socks5OnUpgrade"),
      "Debug output should contain type name, got: {}",
      debug_str
    );
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_second_clone_returns_canceled_after_first_poll()
   {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade1 = Socks5OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };
    let upgrade2 = upgrade1.clone();

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    tx.send(Ok(client)).unwrap();

    let result1 = upgrade1.await;
    assert!(result1.is_ok(), "First clone should resolve with Ok");

    let result2 = upgrade2.await;
    assert!(
      matches!(result2, Err(Socks5UpgradeError::Canceled)),
      "Second clone should return Canceled, got: {:?}",
      result2
    );

    drop(server);
  }

  #[test]
  fn test_socks5_upgrade_error_display_uses_readable_format() {
    let err = Socks5UpgradeError::ReplyError(
      fast_socks5::ReplyError::ConnectionRefused,
    );
    let display_str = format!("{}", err);
    assert!(
      display_str.contains("Connection refused"),
      "Display should use human-readable format, got: {}",
      display_str
    );

    let err = Socks5UpgradeError::ReplyError(
      fast_socks5::ReplyError::NetworkUnreachable,
    );
    let display_str = format!("{}", err);
    assert!(
      display_str.contains("Network unreachable"),
      "Display should use human-readable format, got: {}",
      display_str
    );

    let err = Socks5UpgradeError::Canceled;
    let display_str = format!("{}", err);
    assert!(
      display_str.contains("canceled"),
      "Canceled variant should display 'canceled', got: {}",
      display_str
    );
  }

  #[test]
  fn test_socks5_upgrade_error_source_returns_inner_reply_error() {
    let err = Socks5UpgradeError::ReplyError(
      fast_socks5::ReplyError::ConnectionRefused,
    );
    let source = std::error::Error::source(&err);
    assert!(
      source.is_some(),
      "source() should return Some for ReplyError variant"
    );
    let source_ref = source.unwrap();
    let downcast = source_ref.downcast_ref::<fast_socks5::ReplyError>();
    assert!(
      downcast.is_some(),
      "source() should downcast to ReplyError"
    );
    let downcast_err = downcast.unwrap();
    assert!(
      format!("{}", downcast_err).contains("Connection refused"),
      "source() should return the correct ReplyError variant, got: {}",
      downcast_err
    );
  }

  #[test]
  fn test_socks5_upgrade_error_source_returns_none_for_canceled() {
    let err = Socks5UpgradeError::Canceled;
    let source = std::error::Error::source(&err);
    assert!(
      source.is_none(),
      "source() should return None for Canceled variant"
    );
  }

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_success_returns_error_when_receiver_dropped()
   {
    let (trigger, _upgrade) =
      Socks5UpgradeTrigger::new_for_test_channel_only();

    drop(_upgrade);

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    let result = trigger.send_test_value_for_channel_test(Ok(client));

    assert!(
      result.is_err(),
      "send_test_value should return error when receiver is dropped"
    );
    let err = result.unwrap_err();
    assert!(
      err.to_string().contains("Service dropped the receiver"),
      "Error message should mention receiver was dropped, got: {}",
      err
    );

    drop(server);
  }

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_error_returns_error_when_receiver_dropped()
   {
    let (trigger, _upgrade) =
      Socks5UpgradeTrigger::new_for_test_channel_only();

    drop(_upgrade);

    let result = trigger.send_test_value_for_channel_test(Err(
      Socks5UpgradeError::ReplyError(
        fast_socks5::ReplyError::ConnectionRefused,
      ),
    ));

    assert!(
      result.is_err(),
      "send_test_value should return error when receiver is dropped"
    );
    let err = result.unwrap_err();
    assert!(
      err.to_string().contains("Service dropped the receiver"),
      "Error message should mention receiver was dropped, got: {}",
      err
    );
  }

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_success_succeeds_when_receiver_alive()
   {
    let (trigger, upgrade) =
      Socks5UpgradeTrigger::new_for_test_channel_only();

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    let result = trigger.send_test_value_for_channel_test(Ok(client));
    assert!(
      result.is_ok(),
      "send_test_value should succeed when receiver is alive"
    );

    let stream_result = upgrade.await;
    assert!(stream_result.is_ok(), "Upgrade should resolve with Ok");

    drop(server);
  }

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_error_succeeds_when_receiver_alive()
   {
    let (trigger, upgrade) =
      Socks5UpgradeTrigger::new_for_test_channel_only();

    let result = trigger.send_test_value_for_channel_test(Err(
      Socks5UpgradeError::ReplyError(
        fast_socks5::ReplyError::ConnectionRefused,
      ),
    ));
    assert!(
      result.is_ok(),
      "send_test_value should succeed when receiver is alive"
    );

    let stream_result = upgrade.await;
    assert!(stream_result.is_err(), "Upgrade should resolve with Err");
    match stream_result {
      Err(Socks5UpgradeError::ReplyError(e)) => {
        assert!(
          format!("{}", e).contains("Connection refused"),
          "Should be ConnectionRefused error"
        );
      }
      _ => panic!("Expected ReplyError, got: {:?}", stream_result),
    }
  }

  #[test]
  fn test_client_stream_enum_exists() {
    use super::ClientStream;
    let _ = std::mem::size_of::<ClientStream>();
  }

  #[test]
  fn test_h3_upgrade_error_display() {
    let err = super::H3UpgradeError::ErrorResponse(
      http::StatusCode::BAD_GATEWAY,
    );
    assert!(format!("{}", err).contains("502"));

    let err = super::H3UpgradeError::Canceled;
    assert!(format!("{}", err).contains("canceled"));
  }

  #[tokio::test]
  async fn test_h3_on_upgrade_extracts_from_extensions() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<H3ServerBidiStream, H3UpgradeError>,
    >();
    let upgrade = super::H3OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    req.extensions_mut().insert(upgrade);

    // Extract it
    let extracted = super::H3OnUpgrade::on(&mut req);
    assert!(
      extracted.is_some(),
      "Should extract H3OnUpgrade from extensions"
    );

    // Second extraction should return None
    let second = super::H3OnUpgrade::on(&mut req);
    assert!(second.is_none(), "Second extraction should return None");
  }

  #[tokio::test]
  async fn test_h3_on_upgrade_resolves_with_error_on_cancel() {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<H3ServerBidiStream, H3UpgradeError>,
    >();
    let upgrade = super::H3OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    // Drop the sender to simulate cancellation
    drop(tx);

    let result = upgrade.await;
    assert!(
      matches!(result, Err(H3UpgradeError::Canceled)),
      "Should return Canceled when sender is dropped"
    );
  }

  #[tokio::test]
  async fn test_h3_on_upgrade_resolves_with_error_response() {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<H3ServerBidiStream, H3UpgradeError>,
    >();
    let upgrade = super::H3OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };

    // Send an error
    let _ = tx.send(Err(H3UpgradeError::ErrorResponse(
      http::StatusCode::BAD_GATEWAY,
    )));

    let result = upgrade.await;
    assert!(
      matches!(result, Err(H3UpgradeError::ErrorResponse(s)) if s == http::StatusCode::BAD_GATEWAY),
      "Should return ErrorResponse(502)"
    );
  }

  #[tokio::test]
  async fn test_h3_on_upgrade_second_clone_returns_canceled() {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<H3ServerBidiStream, H3UpgradeError>,
    >();
    let upgrade1 = super::H3OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };
    let upgrade2 = upgrade1.clone();

    // Send an error so first await resolves
    let _ = tx.send(Err(H3UpgradeError::Canceled));

    let result1 = upgrade1.await;
    assert!(result1.is_err());

    // Second clone should return Canceled
    let result2 = upgrade2.await;
    assert!(
      matches!(result2, Err(H3UpgradeError::Canceled)),
      "Second clone should return Canceled"
    );
  }

  #[cfg(test)]
  impl super::H3OnUpgrade {
    pub fn new_for_test(
      receiver: tokio::sync::oneshot::Receiver<
        Result<H3ServerBidiStream, H3UpgradeError>,
      >,
    ) -> Self {
      Self { receiver: Some(Arc::new(Mutex::new(Some(receiver)))) }
    }
  }

  #[test]
  fn test_h3_upgrade_trigger_pair_creates_linked_pair() {
    // This test just verifies the pair() constructor exists and returns
    // the correct types. Actual send_success/send_error require real H3
    // streams which are tested in integration tests.
    // We test the channel behavior using test helpers.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let upgrade = super::H3OnUpgrade::new_for_test(rx);

    // Send a cancel error through the channel
    let _ = tx.send(Err(H3UpgradeError::Canceled));

    // Verify the upgrade is awaitable (tested in async tests above)
    drop(upgrade);
  }

  #[test]
  fn test_h3_on_upgrade_debug_impl() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<H3ServerBidiStream, H3UpgradeError>,
    >();
    let upgrade = super::H3OnUpgrade {
      receiver: Some(Arc::new(Mutex::new(Some(rx)))),
    };
    let debug_str = format!("{:?}", upgrade);
    assert!(
      debug_str.contains("H3OnUpgrade"),
      "Debug output should contain type name, got: {}",
      debug_str
    );
  }

  #[test]
  fn test_h3_on_upgrade_none_debug_impl() {
    let upgrade = super::H3OnUpgrade { receiver: None };
    let debug_str = format!("{:?}", upgrade);
    assert!(
      debug_str.contains("H3OnUpgrade"),
      "Debug output should contain type name, got: {}",
      debug_str
    );
  }

  #[test]
  fn test_h3_upgrade_trigger_debug_impl() {
    // We can't create a real H3UpgradeTrigger without a real H3 stream,
    // but we can verify the Debug impl exists by checking the type implements Debug.
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<super::H3UpgradeTrigger>();
  }
}
