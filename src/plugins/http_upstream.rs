use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};

use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::tracker::StreamTracker;

use self::config::HttpUpstreamPluginConfig;
use self::upstream::UpstreamRegistry;

mod config;
mod error;
mod inherit;
mod service;
mod upstream;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Plugin
// ============================================================================

struct HttpUpstreamPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  registry: Rc<RefCell<UpstreamRegistry>>,
  is_uninstalled: Rc<AtomicBool>,
}

impl HttpUpstreamPlugin {
  fn new(registry: UpstreamRegistry) -> Self {
    let stream_tracker = Rc::new(StreamTracker::new());
    let registry = Rc::new(RefCell::new(registry));

    let upstream_st = stream_tracker.clone();
    let upstream_registry = registry.clone();
    let upstream_builder: Box<dyn BuildService> = Box::new(
      move |args: SerializedArgs| -> Result<Service> {
        service::UpstreamService::new(
          args,
          upstream_st.clone(),
          upstream_registry.clone(),
        )
      },
    );

    let mut service_builders = HashMap::new();
    service_builders.insert("upstream", upstream_builder);

    Self {
      service_builders,
      stream_tracker,
      registry,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }
}

impl Plugin for HttpUpstreamPlugin {
  fn service_builder(&self, name: &str) -> Option<&Box<dyn BuildService>> {
    self.service_builders.get(name)
  }

  fn uninstall(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    if self.is_uninstalled.swap(true, Ordering::SeqCst) {
      return Box::pin(async {});
    }

    let st = self.stream_tracker.clone();
    let registry = self.registry.clone();

    Box::pin(async move {
      info!("http_upstream: starting graceful shutdown");
      st.shutdown();

      match st.wait_shutdown_with_timeout(SHUTDOWN_TIMEOUT).await {
        Ok(()) => info!("http_upstream: all tunnels closed gracefully"),
        Err(_) => {
          warn!(
            "http_upstream: shutdown timed out after {SHUTDOWN_TIMEOUT:?}, \
             forcing close"
          );
          st.abort_all();
          st.drain().await;
        }
      }

      registry.borrow_mut().close_all();
      info!("http_upstream: shutdown complete");
    })
  }
}

// ============================================================================
// Plugin Factory
// ============================================================================

pub fn plugin_name() -> &'static str {
  "http_upstream"
}

pub fn create_plugin(config: Option<&SerializedArgs>) -> Box<dyn Plugin> {
  let plugin_config: HttpUpstreamPluginConfig = match config {
    Some(args) => serde_yaml::from_value(args.clone())
      .expect("invalid http_upstream plugin config"),
    None => HttpUpstreamPluginConfig::default(),
  };

  let tracker = Rc::new(StreamTracker::new());
  let registry = UpstreamRegistry::new(&plugin_config, tracker)
    .expect("failed to initialize http_upstream registry");

  info!(
    "http_upstream: initialized with {} upstream(s)",
    registry.resolved.len()
  );

  Box::new(HttpUpstreamPlugin::new(registry))
}
