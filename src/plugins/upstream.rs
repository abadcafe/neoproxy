//! Upstream plugin — proxy directly or through HTTP/HTTPS/H3/SOCKS5
//! peers.
//!
//! module: upstream
//! responsibilities: forward requests and CONNECT tunnels to upstream
//! servers public operations: plugin_name, create_plugin
//! data entities: UpstreamPlugin
//! tests: service::tests, config::tests, error::tests, inherit::tests,
//! target_parser_tests.rs, upstream child module tests

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tracing::{info, warn};

use self::client::UpstreamRegistry;
use self::config::UpstreamPluginConfig;
use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildService, Service};
use crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT;
use crate::task_tracker::TaskTracker;

mod client;
mod config;
pub(crate) mod egress;
#[cfg(test)]
mod egress_tests;
mod error;
mod inherit;
mod service;
mod target_parser;
mod tunnel_log;
#[cfg(test)]
mod tunnel_log_tests;

#[cfg(test)]
mod client_tests;
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

// ============================================================================
// Plugin
// ============================================================================

struct UpstreamPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  sessions: std::sync::Arc<TaskTracker>,
  registry: Rc<UpstreamRegistry>,
  operations: std::sync::Arc<TaskTracker>,
  is_uninstalled: Rc<AtomicBool>,
}

impl UpstreamPlugin {
  fn new(
    registry: UpstreamRegistry,
    sessions: std::sync::Arc<TaskTracker>,
    operations: std::sync::Arc<TaskTracker>,
  ) -> Self {
    let registry = Rc::new(registry);

    let upstream_st = sessions.clone();
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
      sessions,
      registry,
      operations,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }
}

impl Plugin for UpstreamPlugin {
  fn service_builder(&self, name: &str) -> Option<&dyn BuildService> {
    self.service_builders.get(name).map(|b| b.as_ref())
  }

  fn uninstall(
    &self,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    if self.is_uninstalled.swap(true, Ordering::SeqCst) {
      return Box::pin(async {});
    }

    let st = self.sessions.clone();
    let registry = self.registry.clone();
    let operations = self.operations.clone();

    Box::pin(async move {
      info!("upstream: starting graceful shutdown");
      // Established tunnels have no HTTP message completion boundary.
      // Stop transfers now, then wait for cleanup; this timeout is not
      // a grace period for continued tunnel traffic. Listener draining
      // has already allowed ordinary HTTP exchanges to finish first.
      let deadline =
        tokio::time::Instant::now() + SERVICE_SHUTDOWN_TIMEOUT;
      st.shutdown();

      match st
        .wait_shutdown_with_timeout(SERVICE_SHUTDOWN_TIMEOUT)
        .await
      {
        Ok(()) => {
          info!("upstream: all streams closed gracefully")
        }
        Err(_) => {
          warn!(
            "upstream: shutdown timed out after \
             {SERVICE_SHUTDOWN_TIMEOUT:?}, forcing close"
          );
          st.abort_all();
          st.drain().await;
        }
      }

      // Bridges/drivers support tunnel cleanup, so their notification
      // follows tunnel completion. Both groups share one phase budget.
      operations
        .graceful_shutdown(
          deadline
            .saturating_duration_since(tokio::time::Instant::now()),
        )
        .await;
      // Active operations have released their streams/leases. Only
      // now release this plugin's transport resources; shared pools
      // remain owned by the process until every worker has drained.
      registry.close_all();
      info!("upstream: shutdown complete");
    })
  }
}

// ============================================================================
// Plugin Factory
// ============================================================================

pub(crate) fn plugin_name() -> &'static str {
  "upstream"
}

pub(crate) fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  let connection_pools = build_connection_pools(config)?;
  create_pooled_plugin(config, connection_pools)
}

pub(crate) use client::ConnectionPools;
pub(crate) fn build_connection_pools(
  config: Option<&SerializedArgs>,
) -> Result<std::sync::Arc<ConnectionPools>> {
  let config: UpstreamPluginConfig = config
    .map(|args| serde_yaml::from_value(args.clone()))
    .transpose()?
    .unwrap_or_default();
  config::merge_chain_config(&config)?;
  ConnectionPools::new(
    config::connection_pool::resolve_connection_pools(&config)?,
  )
}

pub(crate) fn create_pooled_plugin(
  config: Option<&SerializedArgs>,
  connection_pools: std::sync::Arc<ConnectionPools>,
) -> Result<Box<dyn Plugin>> {
  let plugin_config: UpstreamPluginConfig = match config {
    Some(args) => serde_yaml::from_value(args.clone())?,
    None => UpstreamPluginConfig::default(),
  };

  let upstreams = config::merge_chain_config(&plugin_config)?;

  let tracker = std::sync::Arc::new(TaskTracker::new());
  let sessions = std::sync::Arc::new(TaskTracker::new());
  let registry = UpstreamRegistry::with_connection_pools(
    upstreams,
    tracker.clone(),
    connection_pools,
  )?;

  info!("upstream: initialized with {} upstream(s)", registry.len());

  Ok(Box::new(UpstreamPlugin::new(registry, sessions, tracker)))
}
