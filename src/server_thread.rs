use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use anyhow::Result;
use tokio::{runtime, sync, task};
use tracing::{error, warn};

use crate::config::Config;
use crate::listener::Listener;
use crate::listeners::ListenerManager;
use crate::plugins::PluginManager;
use crate::server;
use crate::service::Service;

/// Build a service by name, wrapping it with configured layers.
///
/// Layers are applied in reverse order: config lists [outer, inner],
/// build iterates .rev() to apply inner first, then outer.
pub(crate) fn build_service_with_layers(
  plugin_manager: &PluginManager,
  config: &Config,
  service_name: &str,
) -> Result<Service> {
  let sc = config.service_by_name(service_name).ok_or_else(|| {
    anyhow::anyhow!("service '{}' not found", service_name)
  })?;

  let mut service = plugin_manager.build_service(
    sc.plugin_name(),
    sc.kind(),
    sc.args().clone(),
  )?;

  // Wrap with layers (inner to outer)
  for layer_cfg in sc.layers().iter().rev() {
    let layer = plugin_manager.build_layer(
      layer_cfg.plugin_name(),
      layer_cfg.kind(),
      layer_cfg.args().clone(),
    )?;
    service = layer.layer(service);
  }

  Ok(service)
}

/// Build all listeners from config.
///
/// For each server, builds its service (with layers, cached),
/// then groups servers by listener name.
/// For each ListenerConfig, builds a Listener with its servers.
pub(crate) fn build_listeners(
  plugin_manager: &PluginManager,
  config: &Config,
  listener_manager: &ListenerManager,
) -> Result<Vec<Listener>> {
  // Build listener_name -> Vec<server::Server> mapping
  let mut listener_servers: HashMap<String, Vec<server::Server>> =
    HashMap::new();

  // Cache for built services (avoid rebuilding same service)
  let mut service_cache: HashMap<String, Service> = HashMap::new();

  for server_cfg in config.servers() {
    // Build service for this server (with caching)
    let service =
      match service_cache.entry(server_cfg.service().to_string()) {
        Entry::Occupied(e) => e.get().clone(),
        Entry::Vacant(e) => {
          let svc = build_service_with_layers(
            plugin_manager,
            config,
            server_cfg.service(),
          )?;
          e.insert(svc).clone()
        }
      };

    let entry = server::Server {
      hostnames: server_cfg.hostnames().to_vec(),
      service,
      service_name: server_cfg.service().to_string(),
      tls: server_cfg.tls().cloned(),
    };

    for listener_name in server_cfg.listeners() {
      listener_servers
        .entry(listener_name.clone())
        .or_default()
        .push(entry.clone());
    }
  }

  // Build Listener for each ListenerConfig
  let mut listeners = Vec::new();
  for lc in config.listeners() {
    let servers =
      listener_servers.get(lc.name()).cloned().unwrap_or_default();

    let listener = listener_manager.build_listener(
      lc.kind(),
      lc.addresses().to_vec(),
      lc.args().clone(),
      servers,
    )?;

    listeners.push(listener);
  }

  Ok(listeners)
}

/// Run a server thread with listeners built from PluginManager.
///
/// Each server thread creates its own tokio runtime and PluginManager,
/// builds listeners, and runs them concurrently. The thread waits for
/// the shutdown signal, then stops all listeners.
pub(crate) fn run_server_thread(
  shutdown: Arc<sync::Notify>,
  thread_id: usize,
) -> Result<()> {
  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name(format!("neoproxy-server-{}", thread_id))
    .build()?;

  rt.block_on(local_set.run_until(async {
    // Each thread builds its own PluginManager and listeners
    let (mut plugin_manager, plugin_errors) =
      PluginManager::new(Config::global().plugins().clone());
    for err in &plugin_errors {
      warn!("plugin load error: {}: {}", err.name, err.source);
    }
    let listener_manager = ListenerManager::new();

    let listeners = build_listeners(
      &plugin_manager,
      Config::global(),
      &listener_manager,
    )
    .map_err(|e| {
      error!("failed to build listeners: {e}");
      e
    })?;

    let mut join_set = task::JoinSet::new();

    for listener in &listeners {
      join_set.spawn_local(listener.start());
    }

    shutdown.notified().await;

    for listener in &listeners {
      listener.stop();
    }

    while join_set.join_next().await.is_some() {}

    // Drop listeners first so middleware instances (which hold
    // mpsc::Sender clones for access_log writer threads) are
    // released before uninstall(). This ensures the Sender clones
    // are dropped early, allowing writer threads to see channel
    // close and begin their final flush. uninstall() then drops the
    // registry's Sender handles and saves JoinHandles to
    // PENDING_WRITER_JOINS. The actual thread join happens later in
    // flush_writer_threads(), called from main.rs after all server
    // threads have exited (see CR-014 two-phase shutdown design).
    drop(listeners);

    // Uninstall plugins at shutdown
    plugin_manager.uninstall_all().await;

    Ok(())
  }))
}
