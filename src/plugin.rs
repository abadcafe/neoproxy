//! Plugin trait and factory types.
//!
//! This module provides:
//! - `Plugin` trait - interface for plugins to provide service builders
//! - `BuildPlugin` - factory trait for creating plugins

use std::future::Future;
use std::pin::Pin;

use crate::service::{BuildLayer, BuildService};

/// Trait for plugin implementations.
///
/// Plugins provide service builders for handling requests.
/// Each plugin can provide multiple services by name.
pub trait Plugin {
  /// Get a service builder by name.
  ///
  /// Returns `None` if the plugin doesn't provide a service with that
  /// name.
  fn service_builder(
    &self,
    _name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    None
  }

  /// Get a layer builder by name.
  ///
  /// Returns `None` if the plugin doesn't provide a layer with that
  /// name.
  fn layer_builder(&self, _name: &str) -> Option<&Box<dyn BuildLayer>> {
    None
  }

  /// Uninstall the plugin.
  ///
  /// Called when the plugin is being unloaded. Use this to
  /// release resources, close connections, etc.
  ///
  /// The default implementation does nothing.
  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {})
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct TestPlugin;

  impl Plugin for TestPlugin {}

  struct DefaultOnlyPlugin;

  impl Plugin for DefaultOnlyPlugin {}

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

    fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
      let flag = self.uninstalled.clone();
      Box::pin(async move {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
      })
    }
  }

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

    fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
      let delay = self.delay_ms;
      Box::pin(async move {
        tokio::time::sleep(std::time::Duration::from_millis(delay))
          .await;
      })
    }
  }

  #[tokio::test]
  async fn test_uninstall_default_completes_immediately() {
    let plugin = TestPlugin;
    let future = plugin.uninstall();
    let result =
      tokio::time::timeout(std::time::Duration::from_millis(1), future)
        .await;
    assert!(result.is_ok());
  }

  #[tokio::test]
  async fn test_uninstall_default_returns_unit() {
    let plugin = TestPlugin;
    let future = plugin.uninstall();
    let result: () = future.await;
    assert_eq!(result, ());
  }

  #[tokio::test]
  async fn test_uninstall_custom_implementation_is_called() {
    let plugin = CustomUninstallPlugin::new();
    let flag = plugin.get_uninstalled_flag();
    assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));
    plugin.uninstall().await;
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
  }

  #[tokio::test]
  async fn test_uninstall_delayed_implementation() {
    let plugin = DelayedUninstallPlugin::new(50);
    let result_short = tokio::time::timeout(
      std::time::Duration::from_millis(10),
      plugin.uninstall(),
    )
    .await;
    assert!(result_short.is_err());

    let plugin2 = DelayedUninstallPlugin::new(50);
    let result_long = tokio::time::timeout(
      std::time::Duration::from_millis(200),
      plugin2.uninstall(),
    )
    .await;
    assert!(result_long.is_ok());
  }

  #[test]
  fn test_default_service_builder_returns_none() {
    let plugin = DefaultOnlyPlugin;
    let result = plugin.service_builder("any_name");
    assert!(result.is_none());
  }

  #[test]
  fn test_default_layer_builder_returns_none() {
    let plugin = DefaultOnlyPlugin;
    let result = plugin.layer_builder("any_name");
    assert!(result.is_none());
  }

  #[tokio::test]
  async fn test_default_uninstall_completes_immediately() {
    let plugin = DefaultOnlyPlugin;
    let result = tokio::time::timeout(
      std::time::Duration::from_millis(1),
      plugin.uninstall(),
    )
    .await;
    assert!(result.is_ok());
  }
}
