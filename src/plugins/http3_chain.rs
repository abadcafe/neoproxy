use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::{info, warn};

use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::BuildService;
use crate::stream::DEFAULT_IDLE_TIMEOUT_SECS;
use crate::tracker::StreamTracker;

// ============================================================================
// Sub-module Declarations
// ============================================================================

pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod upstream;
pub(crate) mod service;

// Re-exports must come before tests so glob imports resolve
// (kept as documentation of public API surface)
#[cfg(test)]
mod tests;

// ============================================================================
// Constants
// ============================================================================

static ALPN: &[u8] = b"h3";

/// Graceful shutdown timeout for HTTP/3 Chain Service
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Default Idle Timeout
// ============================================================================

pub(crate) fn default_idle_timeout() -> Duration {
  Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
}

// ============================================================================
// Plugin
// ============================================================================

struct Http3ChainPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  is_uninstalled: Rc<AtomicBool>,
}

impl Http3ChainPlugin {
  fn new() -> Self {
    let stream_tracker = Rc::new(StreamTracker::new());
    let st_clone = stream_tracker.clone();
    let builder: Box<dyn BuildService> = Box::new(move |a| {
      service::Http3ChainService::new(a, st_clone.clone())
    });
    let service_builders = HashMap::from([("http3_chain", builder)]);
    Self {
      service_builders,
      stream_tracker,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }

  async fn do_graceful_shutdown(
    stream_tracker: &Rc<StreamTracker>,
  ) {
    stream_tracker.shutdown();
    info!("Http3ChainPlugin: shutdown notification sent");
    stream_tracker.wait_shutdown().await;
    info!("Http3ChainPlugin: all streams completed");
  }
}

impl Plugin for Http3ChainPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    self.service_builders.get(name)
  }

  fn uninstall(&self) -> Pin<Box<dyn Future<Output = ()>>> {
    if self.is_uninstalled.load(Ordering::SeqCst) {
      info!("Http3ChainPlugin: already uninstalled, skipping");
      return Box::pin(async {});
    }
    self.is_uninstalled.store(true, Ordering::SeqCst);

    let initial_stream_count = self.stream_tracker.active_count();
    let stream_tracker = self.stream_tracker.clone();

    Box::pin(async move {
      info!("Http3ChainPlugin: starting graceful shutdown");

      let shutdown_result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        Self::do_graceful_shutdown(&stream_tracker),
      )
      .await;

      match shutdown_result {
        Ok(()) => {
          info!("Http3ChainPlugin: graceful shutdown completed");
        }
        Err(_) => {
          warn!(
            "Http3ChainPlugin: shutdown timeout reached after {:?}, \
             forcefully aborting remaining tasks: {} streams",
            SHUTDOWN_TIMEOUT, initial_stream_count
          );
          stream_tracker.abort_all();
          stream_tracker.drain().await;
          info!("Http3ChainPlugin: forced shutdown completed");
        }
      }

      // Shutdown upstream thread
      let mut th_guard = upstream::UPSTREAM_THREAD_HANDLE.lock().unwrap();
      if let Some(mut handle) = th_guard.take() {
        // Send shutdown signal and drop tx
        let _ = handle.shutdown_tx.try_send(());
        drop(handle.shutdown_tx);

        // Join upstream thread
        if let Some(jh) = handle.join_handle.take() {
          let _ = jh.join();
          info!("Http3ChainPlugin: upstream maintenance thread joined");
        }
      }

      // Close all QUIC connections gracefully
      let mut reg_guard = upstream::UPSTREAM_REGISTRY.lock().unwrap();
      if let Some(ref registry) = *reg_guard {
        let mut closed = 0usize;
        for proxy_arc in registry.pool.values() {
          if let Ok(proxy) = proxy_arc.try_lock() {
            if let Some(ref conn) = proxy.quinn_conn {
              upstream::UpstreamConnection::new(conn.clone()).close();
              closed += 1;
            }
          }
        }
        info!("Http3ChainPlugin: closed {} upstream pool connections", closed);
      }
      // Clear entire registry, dropping all connection references
      *reg_guard = None;
    })
  }
}

pub fn plugin_name() -> &'static str {
  "http3_chain"
}

pub fn create_plugin(config: Option<&SerializedArgs>) -> Box<dyn Plugin> {
  // Parse plugin config and initialize upstream registry
  if let Some(config_value) = config {
    let plugin_config: config::Http3ChainPluginConfig =
      serde_yaml::from_value(config_value.clone())
        .unwrap_or_else(|e| panic!("http3_chain: failed to parse plugin config: {}", e));
    upstream::init_upstream_registry(&plugin_config)
      .unwrap_or_else(|e| panic!("http3_chain: failed to initialize upstream registry: {}", e));
  }
  Box::new(Http3ChainPlugin::new())
}
