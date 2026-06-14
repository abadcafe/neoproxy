use std::future::Future;
use std::pin::Pin;

use crate::plugin::Plugin;

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
  ) -> Option<&dyn crate::service::BuildService> {
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
  ) -> Option<&dyn crate::service::BuildService> {
    None
  }

  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    let delay = self.delay_ms;
    Box::pin(async move {
      tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
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
