//! Access log plugin — file-based access logging.
//!
//! module: access_log
//! responsibilities: log proxy access entries to rotating files
//! public operations: plugin_name, create_plugin
//! data entities: AccessLogPlugin
//! tests: access_log_tests.rs, layer_tests.rs, registry_tests.rs

pub(crate) mod config;
pub(crate) mod context;
pub(crate) mod formatter;
pub(crate) mod layer;
mod paths;
#[cfg(test)]
mod paths_tests;
pub(crate) mod registry;
pub(crate) mod writer;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod formatter_tests;
#[cfg(test)]
mod layer_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod tracing_capture;
#[cfg(test)]
mod tracing_capture_tests;
#[cfg(test)]
mod writer_tests;

use std::collections::HashMap;

use anyhow::Result;

use self::config::{AccessLogConfig, AccessLogPluginConfig};
use self::layer::AccessLogLayer;
use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer};

/// An instance owns a lease on the process registry. Builder closures
/// use Weak references, so uninstall releases this instance's resources
/// promptly.
pub(crate) struct AccessLogPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
  registry: std::cell::RefCell<
    Option<std::sync::Arc<registry::WriterRegistry>>,
  >,
  active: std::rc::Rc<std::cell::Cell<bool>>,
}

pub(crate) fn plugin_name() -> &'static str {
  "access_log"
}

pub(crate) fn build_registry(
  config: Option<&SerializedArgs>,
) -> Result<std::sync::Arc<registry::WriterRegistry>> {
  let config = match config {
    Some(config) => {
      serde_yaml::from_value::<AccessLogPluginConfig>(config.clone())?
    }
    None => AccessLogPluginConfig::default(),
  };
  Ok(std::sync::Arc::new(registry::WriterRegistry::new(&config)?))
}

pub(crate) fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  Ok(create_shared_plugin(build_registry(config)?))
}

pub(crate) fn create_shared_plugin(
  registry: std::sync::Arc<registry::WriterRegistry>,
) -> Box<dyn Plugin> {
  let weak = std::sync::Arc::downgrade(&registry);
  let active = std::rc::Rc::new(std::cell::Cell::new(true));
  let builder_active = active.clone();
  let builder: Box<dyn BuildLayer> = Box::new(move |args| {
    anyhow::ensure!(
      builder_active.get(),
      "access_log plugin has been uninstalled"
    );
    let config: AccessLogConfig = serde_yaml::from_value(args)?;
    let registry = weak
      .upgrade()
      .ok_or_else(|| anyhow::anyhow!("access_log registry stopped"))?;
    let sink = registry.get_writer(&config.writer)?;
    Ok(Layer::new(AccessLogLayer::new(sink, config.context_fields)))
  });
  Box::new(AccessLogPlugin {
    layer_builders: HashMap::from([("file", builder)]),
    registry: std::cell::RefCell::new(Some(registry)),
    active,
  })
}

impl Plugin for AccessLogPlugin {
  fn layer_builder(&self, name: &str) -> Option<&dyn BuildLayer> {
    self.layer_builders.get(name).map(|builder| builder.as_ref())
  }

  fn uninstall(
    &self,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    self.active.set(false);
    let registry = self.registry.borrow_mut().take();
    Box::pin(async move {
      drop(registry);
    })
  }
}
