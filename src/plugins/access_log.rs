//! Access log plugin.

pub mod config;
pub mod context;
pub mod formatter;
pub mod layer;
pub mod registry;
pub mod writer;

#[cfg(test)]
mod build_log_entry_tests;
#[cfg(test)]
mod plugin_integration_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod test_utils;

use std::collections::HashMap;

use self::config::{AccessLogConfig, AccessLogPluginConfig};
use self::layer::AccessLogLayer;
use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer};

/// Timeout for joining writer threads during shutdown.
///
/// If a writer thread does not exit within this duration (e.g., because
/// the filesystem is unresponsive or sender clones are still held by
/// middleware instances), the join is abandoned and the thread is
/// detached. This prevents the shutdown sequence from blocking
/// indefinitely.
pub(crate) const WRITER_JOIN_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(5);

/// Access log plugin providing file layer.
pub struct AccessLogPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
  is_uninstalled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AccessLogPlugin {
  pub fn new(
    is_uninstalled: std::sync::Arc<std::sync::atomic::AtomicBool>,
  ) -> Self {
    let file_layer_builder: Box<dyn BuildLayer> = Box::new(|args| {
      let config: AccessLogConfig = serde_yaml::from_value(args)?;
      let tx = get_writer(&config.writer)?;

      Ok(Layer::new(AccessLogLayer {
        tx,
        context_fields: config.context_fields,
      }))
    });

    Self {
      layer_builders: HashMap::from([("file", file_layer_builder)]),
      is_uninstalled,
    }
  }
}

pub fn plugin_name() -> &'static str {
  "access_log"
}

pub fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Box<dyn Plugin> {
  if let Some(config_value) = config {
    let plugin_config: AccessLogPluginConfig =
      serde_yaml::from_value(config_value.clone()).unwrap_or_else(
        |e| panic!("access_log: failed to parse plugin config: {}", e),
      );
    init_writer_registry(&plugin_config).unwrap_or_else(|e| {
      panic!("access_log: failed to initialize writer registry: {}", e)
    });
  } else {
    init_writer_registry(&AccessLogPluginConfig::default())
      .unwrap_or_else(|e| {
        panic!(
          "access_log: failed to initialize writer registry: {}",
          e
        )
      });
  }
  Box::new(AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  )))
}

impl Plugin for AccessLogPlugin {
  fn layer_builder(&self, name: &str) -> Option<&Box<dyn BuildLayer>> {
    self.layer_builders.get(name)
  }

  fn uninstall(
    &self,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    use std::sync::atomic::Ordering;

    use tracing::warn;

    if self.is_uninstalled.load(Ordering::SeqCst) {
      return Box::pin(async {});
    }
    self.is_uninstalled.store(true, Ordering::SeqCst);

    Box::pin(async {
      let old_registry = {
        let mut guard = self::registry::WRITER_REGISTRY.lock().unwrap();
        guard.take()
      };

      if let Some(registry) = old_registry {
        let mut joins: Vec<(String, std::thread::JoinHandle<()>)> =
          Vec::new();
        for (path_prefix, mut handle) in registry {
          if let Some(jh) = handle.join_handle.take() {
            joins.push((path_prefix, jh));
          }
        }

        for (path_prefix, jh) in joins {
          let (tx, rx) = std::sync::mpsc::channel();
          std::thread::spawn(move || {
            let result = jh.join();
            let _ = tx.send(result);
          });
          match rx.recv_timeout(WRITER_JOIN_TIMEOUT) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
              warn!(
                "access_log: writer thread '{}' panicked",
                path_prefix
              );
            }
            Err(_) => {
              warn!(
                "access_log: writer thread '{}' did not exit within \
                 {:?}, detaching",
                path_prefix, WRITER_JOIN_TIMEOUT
              );
            }
          }
        }
      }
    })
  }
}

#[cfg(test)]
pub use self::registry::LogEntry;
#[cfg(test)]
pub use self::registry::reset_writer_registry;
pub use self::registry::{get_writer, init_writer_registry};
