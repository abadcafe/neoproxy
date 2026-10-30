//! Plugin trait definition.
//!
//! module: plugin
//! responsibilities: define the interface that all plugins must
//! implement public operations: Plugin::service_builder,
//! Plugin::layer_builder, Plugin::monitor, Plugin::uninstall data
//! entities: Plugin (trait) tests: plugin_tests.rs

use std::future::Future;
use std::pin::Pin;

use crate::service::{BuildLayer, BuildService};

/// Trait for plugin implementations.
///
/// Plugins provide service builders for handling requests.
/// Each plugin can provide multiple services by name.
pub(crate) trait Plugin {
  /// Observe background programming failures while the worker is live.
  /// The worker drops this monitor before calling uninstall.
  fn monitor(&self) -> Pin<Box<dyn Future<Output = ()> + '_>> {
    Box::pin(std::future::pending())
  }

  /// Get a service builder by name.
  ///
  /// Returns `None` if the plugin doesn't provide a service with that
  /// name.
  fn service_builder(&self, _name: &str) -> Option<&dyn BuildService> {
    None
  }

  /// Get a layer builder by name.
  ///
  /// Returns `None` if the plugin doesn't provide a layer with that
  /// name.
  fn layer_builder(&self, _name: &str) -> Option<&dyn BuildLayer> {
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
