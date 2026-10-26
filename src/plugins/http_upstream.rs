//! HTTP upstream plugin — proxy to upstream HTTP/HTTPS/H3 servers.
//!
//! module: http_upstream
//! responsibilities: forward requests and CONNECT tunnels to upstream
//! servers public operations: plugin_name, create_plugin
//! data entities: HttpUpstreamPlugin
//! tests: service::tests, config::tests, error::tests, inherit::tests,
//! target_parser_tests.rs, upstream child module tests

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tracing::{info, warn};

use self::config::HttpUpstreamPluginConfig;
use self::upstream::UpstreamRegistry;
use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT;
use crate::tracker::StreamTracker;

mod config;
mod error;
mod inherit;
mod service;
mod target_parser;
mod tunnel_log;
#[cfg(test)]
mod tunnel_log_tests;
mod upstream;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod inherit_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod target_parser_tests;
#[cfg(test)]
mod upstream_tests;

// ============================================================================
// Plugin
// ============================================================================

struct HttpUpstreamPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  registry: Rc<UpstreamRegistry>,
  is_uninstalled: Rc<AtomicBool>,
}

impl HttpUpstreamPlugin {
  fn new(
    registry: UpstreamRegistry,
    stream_tracker: Rc<StreamTracker>,
  ) -> Self {
    let registry = Rc::new(registry);

    let upstream_st = stream_tracker.clone();
    let upstream_registry = registry.clone();
    let upstream_builder: Box<dyn BuildService> =
      Box::new(move |args: SerializedArgs| -> Result<Service> {
        service::UpstreamService::build(
          args,
          upstream_st.clone(),
          upstream_registry.clone(),
        )
      });

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
  fn service_builder(&self, name: &str) -> Option<&dyn BuildService> {
    self.service_builders.get(name).map(|b| b.as_ref())
  }

  fn uninstall(
    &self,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    if self.is_uninstalled.swap(true, Ordering::SeqCst) {
      return Box::pin(async {});
    }

    let st = self.stream_tracker.clone();
    let registry = self.registry.clone();

    Box::pin(async move {
      info!("http_upstream: starting graceful shutdown");
      // Established tunnels have no HTTP message completion boundary.
      // Stop transfers now, then wait for cleanup; this timeout is not
      // a grace period for continued tunnel traffic. Listener draining
      // has already allowed ordinary HTTP exchanges to finish first.
      st.shutdown();
      registry.close_all();

      match st
        .wait_shutdown_with_timeout(SERVICE_SHUTDOWN_TIMEOUT)
        .await
      {
        Ok(()) => {
          info!("http_upstream: all streams closed gracefully")
        }
        Err(_) => {
          warn!(
            "http_upstream: shutdown timed out after \
             {SERVICE_SHUTDOWN_TIMEOUT:?}, forcing close"
          );
          st.abort_all();
          st.drain().await;
        }
      }

      info!("http_upstream: shutdown complete");
    })
  }
}

// ============================================================================
// Plugin Factory
// ============================================================================

pub(crate) fn plugin_name() -> &'static str {
  "http_upstream"
}

pub(crate) fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  let plugin_config: HttpUpstreamPluginConfig = match config {
    Some(args) => serde_yaml::from_value(args.clone())?,
    None => HttpUpstreamPluginConfig::default(),
  };

  if let Some(ref certs) = plugin_config.certificates {
    certs.validate()?;
  }

  let upstreams = config::merge_chain_config(&plugin_config)?;

  let tracker = Rc::new(StreamTracker::new());
  let registry = UpstreamRegistry::new(
    upstreams,
    plugin_config.certificates.as_ref(),
    tracker.clone(),
  )?;

  info!(
    "http_upstream: initialized with {} upstream(s)",
    registry.len()
  );

  Ok(Box::new(HttpUpstreamPlugin::new(registry, tracker)))
}
