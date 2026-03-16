use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use tokio::sync;

/// Shutdown Handle for `Listener`s.
pub struct ShutdownHandle(Arc<sync::Notify>);

impl ShutdownHandle {
  pub fn new() -> Self {
    Self(Arc::new(sync::Notify::new()))
  }

  pub fn shutdown(&self) {
    self.0.notify_waiters()
  }

  pub async fn notified(&self) {
    self.0.notified().await
  }
}

impl Clone for ShutdownHandle {
  fn clone(&self) -> Self {
    Self(self.0.clone())
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

pub struct ServiceBuilder(Box<dyn BuildService>);

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

pub struct ListenerBuilder(Box<dyn BuildListener>);

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
    name: &str,
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

pub struct PluginBuilder(Box<dyn BuildPlugin>);

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
}
