#![allow(clippy::borrowed_box)]
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;

// Re-exports from new modules
pub use crate::connect_utils::{parse_connect_target, ConnectTargetError};
pub use crate::h3_stream::{H3ClientBidiStream, H3ServerBidiStream};
pub use crate::http_types::{
  BytesBufBodyWrapper, Request, RequestBody, Response, ResponseBody,
};
pub use crate::shutdown::ShutdownHandle;
pub use crate::shutdown::StreamTracker;
pub use crate::stream::{
  ClientStream, H3OnUpgrade, H3UpgradeError, H3UpgradeTrigger, Socks5OnUpgrade,
  Socks5UpgradeError, Socks5UpgradeTrigger, http_status_to_socks5_error,
};

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

impl<F> BuildService for F where F: Fn(SerializedArgs) -> Result<Service> {}

/// an alias for shorten complex trait definition.
pub trait BuildListener:
  Fn(SerializedArgs, Service) -> Result<Listener> + Sync + Send
{
}

impl<F> BuildListener for F where
  F: Fn(SerializedArgs, Service) -> Result<Listener> + Sync + Send
{
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
    let mut plugin = TestPlugin;

    let future = plugin.uninstall();

    let result =
      tokio::time::timeout(Duration::from_millis(1), future).await;
    assert!(
      result.is_ok(),
      "Default uninstall should complete immediately"
    );
  }

  #[tokio::test]
  async fn test_uninstall_default_returns_unit() {
    let mut plugin = TestPlugin;

    let future = plugin.uninstall();

    let result: () = future.await;
    assert_eq!(result, ());
  }

  #[tokio::test]
  async fn test_uninstall_returns_pinned_future() {
    let mut plugin = TestPlugin;

    let mut future = plugin.uninstall();

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

    match future.as_mut().poll(&mut cx) {
      Poll::Ready(()) => { /* Success - future completed */ }
      Poll::Pending => {
        panic!("Default uninstall future should be Ready immediately")
      }
    }
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_is_called() {
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    assert!(!flag.load(Ordering::SeqCst));

    plugin.uninstall().await;

    assert!(flag.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_completes() {
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    let result = tokio::time::timeout(
      Duration::from_millis(100),
      plugin.uninstall(),
    )
    .await;

    assert!(result.is_ok(), "Custom uninstall should complete");
    assert!(flag.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_delayed_implementation() {
    let mut plugin = DelayedUninstallPlugin::new(50);

    let result_short = tokio::time::timeout(
      Duration::from_millis(10),
      plugin.uninstall(),
    )
    .await;
    assert!(
      result_short.is_err(),
      "Delayed uninstall should not complete within short timeout"
    );

    let mut plugin2 = DelayedUninstallPlugin::new(50);

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
    let mut plugin = TestPlugin;

    plugin.uninstall().await;
    plugin.uninstall().await;
    plugin.uninstall().await;
  }

  #[tokio::test]
  async fn test_uninstall_custom_can_be_called_multiple_times() {
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    plugin.uninstall().await;
    assert!(flag.load(Ordering::SeqCst));

    flag.store(false, Ordering::SeqCst);

    plugin.uninstall().await;
    assert!(flag.load(Ordering::SeqCst));
  }

  #[test]
  fn test_default_service_builder_returns_none() {
    let plugin = DefaultOnlyPlugin;

    let result = plugin.service_builder("any_name");

    assert!(
      result.is_none(),
      "Default service_builder should return None"
    );
  }

  #[tokio::test]
  async fn test_default_uninstall_completes_immediately_for_default_only_plugin()
   {
    let mut plugin = DefaultOnlyPlugin;

    let result = tokio::time::timeout(
      Duration::from_millis(1),
      plugin.uninstall(),
    )
    .await;

    assert!(
      result.is_ok(),
      "Default uninstall should complete immediately"
    );
  }
}
