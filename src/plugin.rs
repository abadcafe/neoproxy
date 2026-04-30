//! Plugin trait and factory types.
//!
//! This module provides:
//! - `Plugin` trait - interface for plugins to provide service builders
//! - `BuildPlugin` - factory trait for creating plugins

use std::future::Future;
use std::pin::Pin;

use crate::service::BuildService;

/// Trait for plugin implementations.
///
/// Plugins provide service builders for handling requests.
/// Each plugin can provide multiple services by name.
///
/// # Example
///
/// ```ignore
/// struct MyPlugin {
///   service_builders: HashMap<&'static str, Box<dyn BuildService>>,
/// }
///
/// impl Plugin for MyPlugin {
///   fn service_builder(&self, name: &str) -> Option<&Box<dyn BuildService>> {
///     self.service_builders.get(name)
///   }
///
///   fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
///     // Cleanup resources
///     Box::pin(async {})
///   }
/// }
/// ```
pub trait Plugin {
  /// Get a service builder by name.
  ///
  /// Returns `None` if the plugin doesn't provide a service with that name.
  fn service_builder(
    &self,
    _name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    None
  }

  /// Uninstall the plugin.
  ///
  /// Called when the plugin is being unloaded. Use this to
  /// release resources, close connections, etc.
  ///
  /// The default implementation does nothing.
  fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {})
  }
}

/// Factory trait for creating plugins.
///
/// A `BuildPlugin` is a zero-argument function that returns a boxed `Plugin`.
/// Must be `Sync + Send` for concurrent access.
pub trait BuildPlugin: Fn() -> Box<dyn Plugin> + Sync + Send {}

impl<F> BuildPlugin for F where F: Fn() -> Box<dyn Plugin> + Sync + Send {}

#[cfg(test)]
mod tests {
  use super::*;

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
    uninstalled: std::sync::Arc<std::sync::atomic::AtomicBool>,
  }

  impl CustomUninstallPlugin {
    fn new() -> Self {
      Self {
        uninstalled: std::sync::Arc::new(
          std::sync::atomic::AtomicBool::new(false),
        ),
      }
    }

    fn get_uninstalled_flag(
      &self,
    ) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
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
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
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
        tokio::time::sleep(std::time::Duration::from_millis(delay))
          .await;
      })
    }
  }

  #[tokio::test]
  async fn test_uninstall_default_completes_immediately() {
    let mut plugin = TestPlugin;

    let future = plugin.uninstall();

    let result =
      tokio::time::timeout(std::time::Duration::from_millis(1), future)
        .await;
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

    assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));

    plugin.uninstall().await;

    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_completes() {
    let mut plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();

    let result = tokio::time::timeout(
      std::time::Duration::from_millis(100),
      plugin.uninstall(),
    )
    .await;

    assert!(result.is_ok(), "Custom uninstall should complete");
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_delayed_implementation() {
    let mut plugin = DelayedUninstallPlugin::new(50);

    let result_short = tokio::time::timeout(
      std::time::Duration::from_millis(10),
      plugin.uninstall(),
    )
    .await;
    assert!(
      result_short.is_err(),
      "Delayed uninstall should not complete within short timeout"
    );

    let mut plugin2 = DelayedUninstallPlugin::new(50);

    let result_long = tokio::time::timeout(
      std::time::Duration::from_millis(200),
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
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));

    flag.store(false, std::sync::atomic::Ordering::SeqCst);

    plugin.uninstall().await;
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
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
      std::time::Duration::from_millis(1),
      plugin.uninstall(),
    )
    .await;

    assert!(
      result.is_ok(),
      "Default uninstall should complete immediately"
    );
  }
}
