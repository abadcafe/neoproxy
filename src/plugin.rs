#![allow(clippy::borrowed_box)]
use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync;

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
    }
  }
}

/// Shutdown Handle for `Listener`s.
pub struct ShutdownHandle {
  notify: Arc<sync::Notify>,
  is_shutdown: Arc<AtomicBool>,
}

impl ShutdownHandle {
  pub fn new() -> Self {
    Self {
      notify: Arc::new(sync::Notify::new()),
      is_shutdown: Arc::new(AtomicBool::new(false)),
    }
  }

  pub fn shutdown(&self) {
    self.is_shutdown.store(true, Ordering::SeqCst);
    self.notify.notify_waiters()
  }

  pub async fn notified(&self) {
    self.notify.notified().await
  }

  /// Check if shutdown has been triggered
  pub fn is_shutdown(&self) -> bool {
    self.is_shutdown.load(Ordering::SeqCst)
  }
}

impl Clone for ShutdownHandle {
  fn clone(&self) -> Self {
    Self {
      notify: self.notify.clone(),
      is_shutdown: self.is_shutdown.clone(),
    }
  }
}

/// A wrapper for `Bytes` based `Body` types like `Full<Bytes>`,
/// `Empty<Bytes>`, etc in crate `http_body_util`. Through this wrapper,
/// different `Body` implements can be converted into `RequestBody` and
/// `ResponseBody` handily.
pub struct BytesBufBodyWrapper<B, E>(
  Pin<Box<dyn Body<Data = B, Error = E> + Send>>,
);

impl<B, E> BytesBufBodyWrapper<B, E> {
  pub fn new<T>(b: T) -> Self
  where
    T: Body<Data = B, Error = E> + Send + 'static,
    B: Buf,
    E: Error + Send + Sync,
  {
    Self(Box::pin(b))
  }
}

impl<B, E> Body for BytesBufBodyWrapper<B, E>
where
  B: Buf,
  E: Error + Send + Sync + 'static,
{
  type Data = B;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.0.as_mut().poll_frame(cx).map_err(|e| e.into())
  }

  fn is_end_stream(&self) -> bool {
    self.0.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.0.size_hint()
  }
}

pub type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type Request = http::Request<RequestBody>;
pub type Response = http::Response<ResponseBody>;

/// To add `clone()` function to the `Service`. The `Clone` trait can
/// not be added into the type definition of the `Service` directly, in
/// rust only auto traits like `Send`, `Sync` etc can be added into type
/// definitions.
trait CloneService:
  tower::Service<
    Request,
    Error = anyhow::Error,
    Response = Response,
    Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
  >
{
  fn clone_boxed(&self) -> Box<dyn CloneService>;
}

impl<S> CloneService for S
where
  S: tower::Service<
      Request,
      Error = anyhow::Error,
      Response = Response,
      Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
    > + Clone
    + 'static,
{
  fn clone_boxed(&self) -> Box<dyn CloneService> {
    Box::new(self.clone())
  }
}

/// The `Service` that plugins should implement.
/// It is non-`Sync` and `Clone`. Plugins should implement a
/// `tower::Service` and wrap it in this struct.
/// Note: `Service` is a lightweight object that can be cloned and
/// created temporarily, even for each request.
pub struct Service(Box<dyn CloneService>);

impl Service {
  pub fn new<S>(inner: S) -> Self
  where
    S: tower::Service<
        Request,
        Response = Response,
        Error = anyhow::Error,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Clone
      + 'static,
  {
    Self(Box::new(inner))
  }
}

impl tower::Service<Request> for Service {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = Response;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
    self.0.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    self.0.call(req)
  }
}

impl Clone for Service {
  fn clone(&self) -> Self {
    Self(self.0.clone_boxed())
  }
}

impl std::fmt::Debug for Service {
  fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
    fmt.debug_struct("Service").finish()
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
    Arc<std::sync::Mutex<
      Option<
        tokio::sync::oneshot::Receiver<
          Result<tokio::net::TcpStream, Socks5UpgradeError>,
        >,
      >,
    >>,
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

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
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
    let trigger = Self {
      sender,
      proto: Some(proto),
    };
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
  pub async fn send_error(mut self, error: fast_socks5::ReplyError) -> Result<()> {
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
    http::StatusCode::BAD_GATEWAY => fast_socks5::ReplyError::ConnectionRefused,
    http::StatusCode::SERVICE_UNAVAILABLE => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    http::StatusCode::GATEWAY_TIMEOUT => fast_socks5::ReplyError::ConnectionTimeout,
    http::StatusCode::FORBIDDEN => fast_socks5::ReplyError::ConnectionNotAllowed,
    _ => fast_socks5::ReplyError::GeneralFailure,
  }
}

pub trait Listening {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>>;
  fn stop(&self);
}

pub struct Listener(Box<dyn Listening>);

impl Listener {
  pub fn new<L>(l: L) -> Self
  where
    L: Listening + 'static,
  {
    Self(Box::new(l))
  }

  pub fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    self.0.start()
  }

  pub fn stop(&self) {
    self.0.stop()
  }
}

pub type SerializedArgs = serde_yaml::Value;

/// an alias for shorten complex trait definition.
pub trait BuildService: Fn(SerializedArgs) -> Result<Service> {}

impl<F> BuildService for F where F: Fn(SerializedArgs) -> Result<Service>
{}

#[allow(dead_code)]
pub struct ServiceBuilder(Box<dyn BuildService>);

#[allow(dead_code)]
impl ServiceBuilder {
  pub fn new<BS>(bs: BS) -> Self
  where
    BS: BuildService + 'static,
  {
    Self(Box::new(bs))
  }

  pub fn build(&self, args: SerializedArgs) -> Result<Service> {
    self.0(args)
  }
}

/// an alias for shorten complex trait definition.
pub trait BuildListener:
  Fn(SerializedArgs, Service) -> Result<Listener> + Sync + Send
{
}

impl<F> BuildListener for F where
  F: Fn(SerializedArgs, Service) -> Result<Listener> + Sync + Send
{
}

#[allow(dead_code)]
pub struct ListenerBuilder(Box<dyn BuildListener>);

#[allow(dead_code)]
impl ListenerBuilder {
  pub fn new<BL>(bl: BL) -> Self
  where
    BL: BuildListener + 'static,
  {
    Self(Box::new(bl))
  }

  pub fn build(
    &self,
    args: SerializedArgs,
    svc: Service,
  ) -> Result<Listener> {
    self.0(args, svc)
  }
}

pub trait Plugin {
  fn service_builder(
    &self,
    _name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    None
  }

  fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {})
  }
}

/// an alias for shorten complex trait definition.
pub trait BuildPlugin: Fn() -> Box<dyn Plugin> + Sync + Send {}

impl<F> BuildPlugin for F where F: Fn() -> Box<dyn Plugin> + Sync + Send {}

#[allow(dead_code)]
pub struct PluginBuilder(Box<dyn BuildPlugin>);

#[allow(dead_code)]
impl PluginBuilder {
  pub fn new<BP>(bl: BP) -> Self
  where
    BP: BuildPlugin + 'static,
  {
    Self(Box::new(bl))
  }

  pub fn build(&self) -> Box<dyn Plugin> {
    self.0()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::time::Duration;

  /// A simple test plugin that uses the default uninstall implementation.
  struct TestPlugin;

  impl Plugin for TestPlugin {
    fn service_builder(
      &self,
      _name: &str,
    ) -> Option<&Box<dyn BuildService>> {
      None
    }
  }

  /// A test plugin that uses default implementations for both methods.
  /// Used to test the default behavior of the Plugin trait.
  struct DefaultOnlyPlugin;

  impl Plugin for DefaultOnlyPlugin {}

  /// A test plugin with a custom uninstall implementation that completes
  /// immediately with a marker to verify it was called.
  struct CustomUninstallPlugin {
    uninstalled: Arc<AtomicBool>,
  }

  impl CustomUninstallPlugin {
    fn new() -> Self {
      Self { uninstalled: Arc::new(AtomicBool::new(false)) }
    }

    fn get_uninstalled_flag(&self) -> Arc<AtomicBool> {
      self.uninstalled.clone()
    }
  }

  impl Plugin for CustomUninstallPlugin {
    fn service_builder(
      &self,
      _name: &str,
    ) -> Option<&Box<dyn BuildService>> {
      None
    }

    fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
      let flag = self.uninstalled.clone();
      Box::pin(async move {
        flag.store(true, Ordering::SeqCst);
      })
    }
  }

  /// A test plugin with a custom uninstall that has async delay.
  struct DelayedUninstallPlugin {
    delay_ms: u64,
  }

  impl DelayedUninstallPlugin {
    fn new(delay_ms: u64) -> Self {
      Self { delay_ms }
    }
  }

  impl Plugin for DelayedUninstallPlugin {
    fn service_builder(
      &self,
      _name: &str,
    ) -> Option<&Box<dyn BuildService>> {
      None
    }

    fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
      let delay = self.delay_ms;
      Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(delay)).await;
      })
    }
  }

  #[tokio::test]
  async fn test_uninstall_default_completes_immediately() {
    // Arrange: Create a plugin with default uninstall implementation
    let mut plugin = TestPlugin;

    // Act: Call uninstall and verify it completes within a very short timeout
    let future = plugin.uninstall();

    // Assert: Future completes immediately (within 1ms), proving it doesn't
    // hang or have any async wait
    let result =
      tokio::time::timeout(Duration::from_millis(1), future).await;
    assert!(
      result.is_ok(),
      "Default uninstall should complete immediately"
    );
  }

  #[tokio::test]
  async fn test_uninstall_default_returns_unit() {
    // Arrange: Create a plugin with default uninstall implementation
    let mut plugin = TestPlugin;

    // Act: Call uninstall and get the future
    let future = plugin.uninstall();

    // Assert: The future output type is ()
    let result: () = future.await;
    assert_eq!(result, ());
  }

  #[tokio::test]
  async fn test_uninstall_returns_pinned_future() {
    // Arrange: Create a plugin
    let mut plugin = TestPlugin;

    // Act: Call uninstall
    let mut future = plugin.uninstall();

    // Assert: Verify the future can be polled and completes successfully
    // This is a runtime verification, not just type system check
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn dummy_raw_waker() -> RawWaker {
      #[allow(dead_code)]
      fn no_op(_: *const ()) -> RawWaker {
        dummy_raw_waker()
      }
      fn no_op_clone(_: *const ()) -> RawWaker {
        dummy_raw_waker()
      }
      fn no_op_action(_: *const ()) {}

      static VTABLE: RawWakerVTable = RawWakerVTable::new(
        no_op_clone,
        no_op_action,
        no_op_action,
        no_op_action,
      );
      RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(dummy_raw_waker()) };
    let mut cx = Context::from_waker(&waker);

    // Poll the future - it should be ready immediately
    match future.as_mut().poll(&mut cx) {
      Poll::Ready(()) => { /* Success - future completed */ }
      Poll::Pending => {
        panic!("Default uninstall future should be Ready immediately")
      }
    }
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_is_called() {
    // Arrange: Create a plugin with custom uninstall that sets a flag
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    // Assert: Flag is initially false
    assert!(!flag.load(Ordering::SeqCst));

    // Act: Call uninstall and await
    plugin.uninstall().await;

    // Assert: Flag should be set to true by custom implementation
    assert!(flag.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_completes() {
    // Arrange: Create a plugin with custom uninstall
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    // Act: Call uninstall and await with timeout
    let result = tokio::time::timeout(
      Duration::from_millis(100),
      plugin.uninstall(),
    )
    .await;

    // Assert: Should complete within timeout and flag should be set
    assert!(result.is_ok(), "Custom uninstall should complete");
    assert!(flag.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_delayed_implementation() {
    // Arrange: Create a plugin with a delayed uninstall (50ms delay)
    let mut plugin = DelayedUninstallPlugin::new(50);

    // Act & Assert: Should not complete within 10ms
    let result_short = tokio::time::timeout(
      Duration::from_millis(10),
      plugin.uninstall(),
    )
    .await;
    assert!(
      result_short.is_err(),
      "Delayed uninstall should not complete within short timeout"
    );

    // Arrange: Create another plugin with delayed uninstall
    let mut plugin2 = DelayedUninstallPlugin::new(50);

    // Act & Assert: Should complete within 200ms
    let result_long = tokio::time::timeout(
      Duration::from_millis(200),
      plugin2.uninstall(),
    )
    .await;
    assert!(
      result_long.is_ok(),
      "Delayed uninstall should complete within long timeout"
    );
  }

  #[tokio::test]
  async fn test_uninstall_default_can_be_called_multiple_times() {
    // Arrange: Create a plugin with default uninstall
    let mut plugin = TestPlugin;

    // Act: Call uninstall multiple times
    plugin.uninstall().await;
    plugin.uninstall().await;
    plugin.uninstall().await;

    // Assert: No panic or error (implicit success)
  }

  #[tokio::test]
  async fn test_uninstall_custom_can_be_called_multiple_times() {
    // Arrange: Create a plugin with custom uninstall
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    // Act: Call uninstall first time
    plugin.uninstall().await;
    assert!(flag.load(Ordering::SeqCst));

    // Reset flag
    flag.store(false, Ordering::SeqCst);

    // Act: Call uninstall second time
    plugin.uninstall().await;
    // Assert: Flag should be set again
    assert!(flag.load(Ordering::SeqCst));
  }

  #[test]
  fn test_default_service_builder_returns_none() {
    // Arrange: Create a plugin that uses default service_builder
    let plugin = DefaultOnlyPlugin;

    // Act: Call service_builder with any name
    let result = plugin.service_builder("any_name");

    // Assert: Default implementation should return None
    assert!(
      result.is_none(),
      "Default service_builder should return None"
    );
  }

  #[tokio::test]
  async fn test_default_uninstall_completes_immediately_for_default_only_plugin()
   {
    // Arrange: Create a plugin that uses all default implementations
    let mut plugin = DefaultOnlyPlugin;

    // Act: Call uninstall and verify it completes immediately
    let result = tokio::time::timeout(
      Duration::from_millis(1),
      plugin.uninstall(),
    )
    .await;

    // Assert: Should complete immediately
    assert!(
      result.is_ok(),
      "Default uninstall should complete immediately"
    );
  }

  // ============== ShutdownHandle Tests ==============

  #[test]
  fn test_shutdown_handle_new_is_not_shutdown() {
    // Arrange & Act: Create a new ShutdownHandle
    let handle = ShutdownHandle::new();

    // Assert: Should not be in shutdown state initially
    assert!(
      !handle.is_shutdown(),
      "New ShutdownHandle should not be in shutdown state"
    );
  }

  #[test]
  fn test_shutdown_handle_is_shutdown_after_shutdown() {
    // Arrange: Create a new ShutdownHandle
    let handle = ShutdownHandle::new();

    // Act: Trigger shutdown
    handle.shutdown();

    // Assert: Should be in shutdown state
    assert!(
      handle.is_shutdown(),
      "ShutdownHandle should be in shutdown state after shutdown() is called"
    );
  }

  #[test]
  fn test_shutdown_handle_clone_shares_state() {
    // Arrange: Create a new ShutdownHandle and clone it
    let handle = ShutdownHandle::new();
    let cloned = handle.clone();

    // Act: Trigger shutdown on original
    handle.shutdown();

    // Assert: Clone should also show shutdown state
    assert!(
      cloned.is_shutdown(),
      "Cloned ShutdownHandle should share shutdown state"
    );
  }

  #[test]
  fn test_shutdown_handle_multiple_shutdown_calls() {
    // Arrange: Create a new ShutdownHandle
    let handle = ShutdownHandle::new();

    // Act: Call shutdown multiple times
    handle.shutdown();
    handle.shutdown();
    handle.shutdown();

    // Assert: Should still be in shutdown state (no panic or error)
    assert!(
      handle.is_shutdown(),
      "Multiple shutdown calls should not cause issues"
    );
  }

  #[test]
  fn test_shutdown_handle_multiple_clones() {
    // Arrange: Create a new ShutdownHandle and multiple clones
    let handle = ShutdownHandle::new();
    let clone1 = handle.clone();
    let clone2 = clone1.clone();
    let clone3 = handle.clone();

    // Act: Trigger shutdown on one clone
    clone2.shutdown();

    // Assert: All handles should show shutdown state
    assert!(handle.is_shutdown(), "Original should show shutdown");
    assert!(clone1.is_shutdown(), "Clone1 should show shutdown");
    assert!(clone2.is_shutdown(), "Clone2 should show shutdown");
    assert!(clone3.is_shutdown(), "Clone3 should show shutdown");
  }

  #[tokio::test]
  async fn test_shutdown_handle_notified_after_shutdown() {
    // Arrange: Create a new ShutdownHandle
    let handle = ShutdownHandle::new();
    let handle_clone = handle.clone();

    // Act: Spawn a task that waits for notification
    let notified = tokio::spawn(async move {
      handle_clone.notified().await;
      true
    });

    // Give the task time to start waiting
    tokio::task::yield_now().await;

    // Trigger shutdown
    handle.shutdown();

    // Assert: The notified task should complete quickly
    let result =
      tokio::time::timeout(Duration::from_millis(100), notified).await;

    assert!(
      result.is_ok(),
      "notified() should complete after shutdown()"
    );
    assert!(
      result.unwrap().unwrap(),
      "notified() should have completed"
    );
  }

  // ============== Socks5OnUpgrade Tests ==============

  #[tokio::test]
  async fn test_socks5_on_upgrade_extracts_from_extensions() {
    // Create a request with Socks5OnUpgrade in extensions
    let (_tx, rx) = tokio::sync::oneshot::channel();
    let upgrade = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };

    let mut req = http::Request::builder()
      .method(http::Method::CONNECT)
      .uri("example.com:443")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    req.extensions_mut().insert(upgrade);

    // Extract it
    let extracted = Socks5OnUpgrade::on(&mut req);
    assert!(
      extracted.is_some(),
      "Should extract Socks5OnUpgrade from extensions"
    );

    // Second extraction should return None
    let second = Socks5OnUpgrade::on(&mut req);
    assert!(second.is_none(), "Second extraction should return None");
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_is_available() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };

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
    // Create a socket pair
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
      .await
      .unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client.unwrap();
    let (server, _) = server_res.unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let upgrade = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };

    // Send the stream through the channel
    tx.send(Ok(client)).ok();

    // Await the upgrade
    let result = upgrade.await;
    assert!(result.is_ok(), "Upgrade should resolve with Ok");

    drop(server);
  }

  #[tokio::test]
  async fn test_socks5_on_upgrade_resolves_with_error_on_cancel() {
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };

    // Drop the sender to simulate cancellation
    drop(tx);

    let result = upgrade.await;
    assert!(
      result.is_err(),
      "Upgrade should resolve with Err on cancel"
    );
  }

  #[test]
  fn test_http_status_to_socks5_error_mappings() {
    // BAD_GATEWAY (502) -> ConnectionRefused (target refused)
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::BAD_GATEWAY).as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_REFUSED
    );
    // GATEWAY_TIMEOUT (504) -> ConnectionTimeout (REP=0x06 TTL expired)
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::GATEWAY_TIMEOUT).as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_TTL_EXPIRED
    );
    // SERVICE_UNAVAILABLE (503) -> ConnectionNotAllowed (service denied / shutting down)
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::SERVICE_UNAVAILABLE)
        .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED
    );
    // FORBIDDEN (403) -> ConnectionNotAllowed (access denied / shutting down)
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::FORBIDDEN).as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED
    );
    // Default -> GeneralFailure
    assert_eq!(
      http_status_to_socks5_error(http::StatusCode::INTERNAL_SERVER_ERROR)
        .as_u8(),
      fast_socks5::consts::SOCKS5_REPLY_GENERAL_FAILURE
    );
  }

  #[test]
  fn test_socks5_on_upgrade_debug_impl() {
    let (_tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };
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
  async fn test_socks5_on_upgrade_second_clone_returns_canceled_after_first_poll() {
    // After the first clone resolves the future, a second clone polling
    // the same shared receiver should return Canceled instead of panicking.
    let (tx, rx) = tokio::sync::oneshot::channel::<
      Result<tokio::net::TcpStream, Socks5UpgradeError>,
    >();
    let upgrade1 = Socks5OnUpgrade { receiver: Some(Arc::new(Mutex::new(Some(rx)))) };
    let upgrade2 = upgrade1.clone();

    // Send a value so the first await resolves
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
      .await
      .unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) =
      tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    tx.send(Ok(client)).unwrap();

    // First clone resolves successfully
    let result1 = upgrade1.await;
    assert!(result1.is_ok(), "First clone should resolve with Ok");

    // Second clone should return Canceled, NOT panic
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
    // Verify that Display uses the human-readable ReplyError messages
    // (e.g., "Connection refused") rather than Debug format (e.g., "ConnectionRefused")
    let err = Socks5UpgradeError::ReplyError(fast_socks5::ReplyError::ConnectionRefused);
    let display_str = format!("{}", err);
    assert!(
      display_str.contains("Connection refused"),
      "Display should use human-readable format, got: {}",
      display_str
    );

    let err = Socks5UpgradeError::ReplyError(fast_socks5::ReplyError::NetworkUnreachable);
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
    // Verify that std::error::Error::source() returns the inner ReplyError
    // for the ReplyError variant, enabling error chain inspection.
    let err = Socks5UpgradeError::ReplyError(
      fast_socks5::ReplyError::ConnectionRefused,
    );
    let source = std::error::Error::source(&err);
    assert!(
      source.is_some(),
      "source() should return Some for ReplyError variant"
    );
    // Verify the source is the correct ReplyError type
    let source_ref = source.unwrap();
    let downcast = source_ref.downcast_ref::<fast_socks5::ReplyError>();
    assert!(
      downcast.is_some(),
      "source() should downcast to ReplyError"
    );
    // Compare via Display since ReplyError does not implement PartialEq
    let downcast_err = downcast.unwrap();
    assert!(
      format!("{}", downcast_err).contains("Connection refused"),
      "source() should return the correct ReplyError variant, got: {}",
      downcast_err
    );
  }

  #[test]
  fn test_socks5_upgrade_error_source_returns_none_for_canceled() {
    // Verify that std::error::Error::source() returns None for Canceled variant
    let err = Socks5UpgradeError::Canceled;
    let source = std::error::Error::source(&err);
    assert!(
      source.is_none(),
      "source() should return None for Canceled variant"
    );
  }

  // ============== Socks5UpgradeTrigger Channel Tests ==============

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_success_returns_error_when_receiver_dropped() {
    // Test that send_success returns an appropriate error when the Service
    // has dropped the receiver before the reply was delivered.
    // This tests the channel error handling path that would occur if:
    // 1. Service times out waiting for upgrade
    // 2. Service drops the Socks5OnUpgrade
    // 3. Listener tries to send the stream
    let (trigger, _upgrade) = Socks5UpgradeTrigger::new_for_test_channel_only();

    // Drop the upgrade (receiver side) to simulate Service dropping it
    drop(_upgrade);

    // Create a dummy stream for the test
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) = tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    // Attempt to send - should fail because receiver is dropped
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
  async fn test_socks5_upgrade_trigger_send_error_returns_error_when_receiver_dropped() {
    // Test that send_error returns an appropriate error when the Service
    // has dropped the receiver before the error reply was delivered.
    let (trigger, _upgrade) = Socks5UpgradeTrigger::new_for_test_channel_only();

    // Drop the upgrade (receiver side)
    drop(_upgrade);

    // Attempt to send an error - should fail because receiver is dropped
    let result = trigger.send_test_value_for_channel_test(Err(
      Socks5UpgradeError::ReplyError(fast_socks5::ReplyError::ConnectionRefused),
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
  async fn test_socks5_upgrade_trigger_send_success_succeeds_when_receiver_alive() {
    // Test that send succeeds when the receiver is still alive
    let (trigger, upgrade) = Socks5UpgradeTrigger::new_for_test_channel_only();

    // Create a dummy stream for the test
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_fut = tokio::net::TcpStream::connect(addr);
    let (client_res, server_res) = tokio::join!(client_fut, listener.accept());
    let client = client_res.unwrap();
    let (server, _) = server_res.unwrap();

    // Send should succeed
    let result = trigger.send_test_value_for_channel_test(Ok(client));
    assert!(
      result.is_ok(),
      "send_test_value should succeed when receiver is alive"
    );

    // The upgrade should resolve with the stream
    let stream_result = upgrade.await;
    assert!(
      stream_result.is_ok(),
      "Upgrade should resolve with Ok"
    );

    drop(server);
  }

  #[tokio::test]
  async fn test_socks5_upgrade_trigger_send_error_succeeds_when_receiver_alive() {
    // Test that send_error succeeds when the receiver is still alive
    let (trigger, upgrade) = Socks5UpgradeTrigger::new_for_test_channel_only();

    // Send an error
    let result = trigger.send_test_value_for_channel_test(Err(
      Socks5UpgradeError::ReplyError(fast_socks5::ReplyError::ConnectionRefused),
    ));
    assert!(
      result.is_ok(),
      "send_test_value should succeed when receiver is alive"
    );

    // The upgrade should resolve with the error
    let stream_result = upgrade.await;
    assert!(
      stream_result.is_err(),
      "Upgrade should resolve with Err"
    );
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

  // ============== ClientStream Tests ==============

  #[test]
  fn test_client_stream_enum_exists() {
    // Verify that ClientStream enum is accessible and has the expected variants
    use super::ClientStream;

    // Just verify the type exists and has the expected structure
    // Actual stream testing requires tokio runtime and would be integration-level
    let _ = std::mem::size_of::<ClientStream>();
  }
}
