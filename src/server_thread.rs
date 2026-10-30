//! module: server_thread
//! responsibility: compose and supervise one worker service graph
//! public operations: build_service_with_layers, build_listeners,
//! run_server_thread
//! data entities: none
//! tests: server_thread_tests.rs

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use anyhow::Result;
use tokio::task;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::listener::Listener;
use crate::listeners::ListenerManager;
use crate::plugins::PluginManager;
use crate::server;
use crate::service::Service;
use crate::worker_shutdown::WorkerShutdown;

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
    let lc: &crate::config::ListenerConfig = lc;
    // TLS listeners aggregate certificates and client CA roots only
    // from these associated servers, never from the entire config.
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
/// the shutdown signal, then stops all listeners. Configuration is
/// borrowed from the enclosing thread scope for the worker's lifetime.
pub(crate) fn run_server_thread(
  config: &Config,
  log_registry: Option<
    Arc<crate::plugins::access_log::registry::WriterRegistry>,
  >,
  connection_pools: Option<
    Arc<crate::plugins::upstream::ConnectionPools>,
  >,
  policies: Option<Arc<crate::plugins::e2b::SharedPolicies>>,
  mut worker: WorkerShutdown,
  mut readiness: crate::startup::WorkerReadiness,
  thread_id: usize,
) -> Result<()> {
  let shutdown = worker.shutdown_handle();
  crate::worker_runtime::run(async {
    // Each thread builds its own PluginManager and listeners
    let (mut plugin_manager, plugin_errors) =
      PluginManager::with_shared(
        config.plugins().clone(),
        log_registry,
        connection_pools.clone(),
        policies,
      );
    for err in &plugin_errors {
      warn!("plugin load error: {}: {}", err.name, err.source);
    }
    if !plugin_errors.is_empty() {
      plugin_manager.uninstall_all().await;
      anyhow::bail!(
        "plugin initialization failed: {}",
        plugin_errors
          .iter()
          .map(|error| format!("{}: {}", error.name, error.source))
          .collect::<Vec<_>>()
          .join("; ")
      );
    }
    let listener_manager = ListenerManager::new();

    let listeners =
      match build_listeners(&plugin_manager, config, &listener_manager)
      {
        Ok(listeners) => listeners,
        Err(error) => {
          plugin_manager.uninstall_all().await;
          return Err(error);
        }
      };
    let mut join_set = task::JoinSet::new();
    let mut failure = None;
    for listener in &listeners {
      match listener.start() {
        Ok(running) => {
          join_set.spawn_local(running);
        }
        Err(error) => {
          failure = Some(error);
          break;
        }
      }
    }
    if failure.is_none()
      && let Err(error) = readiness.mark_ready()
    {
      failure = Some(error.into());
    }
    if failure.is_some() {
      shutdown.shutdown();
    } else {
      tokio::select! {
        _ = shutdown.notified() => {},
        () = plugin_manager.supervise() => unreachable!("plugin supervision never completes"),
        result = join_set.join_next(), if !join_set.is_empty() => {
          // Notify peers before cleanup/rendezvous. Waiting until this
          // thread returns would leave peers running while it waits for them.
          shutdown.shutdown();
          failure = match result {
            Some(Ok(Err(error))) => Some(error),
            Some(Err(error)) => {
              if error.is_panic() { std::panic::resume_unwind(error.into_panic()); }
              Some(error.into())
            },
            _ => Some(anyhow::anyhow!("listener stopped unexpectedly")),
          };
        }
      }
    }
    drop(readiness);
    // Stop acceptance and let each protocol driver drain its exchanges,
    // including streamed response bodies, within the listener budget.
    // Keep upstream plugin resources alive until those drivers finish.
    for listener in &listeners {
      listener.stop();
    }
    while let Some(result) = join_set.join_next().await {
      let result = result.map_err(|error| {
        if error.is_panic() {
          std::panic::resume_unwind(error.into_panic());
        }
        error
      });
      if failure.is_none() {
        failure = match result {
          Ok(Ok(())) => None,
          Ok(Err(error)) => Some(error),
          Err(error) => Some(error.into()),
        };
      }
    }

    // Plugins own the shutdown order of their operations. In
    // particular, upgraded tunnels must finish before their
    // listener's H3 transport receives its final shutdown
    // notification. Both use one phase deadline rather than
    // accumulating a new timeout per resource.
    let cleanup_deadline = tokio::time::Instant::now()
      + crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT;
    plugin_manager.uninstall_all().await;
    let mut finishing = task::JoinSet::new();
    for listener in &listeners {
      finishing.spawn_local(listener.finish(cleanup_deadline));
    }
    while let Some(result) = finishing.join_next().await {
      if let Err(error) = result {
        if error.is_panic() {
          std::panic::resume_unwind(error.into_panic());
        }
        warn!("listener cleanup cancelled: {error}");
      }
    }

    // Retain endpoints and keep this runtime polling until every worker
    // finishes both phases. Early socket removal changes UDP reuseport
    // routing even though the client's address has not changed.
    info!(
      "worker {thread_id} business shutdown complete; waiting to \
       release transports"
    );
    worker.finish().await;
    if let Some(shared) = &connection_pools {
      shared.close();
    }
    drop(listeners);

    match failure {
      Some(error) => {
        error!("listener failed: {error}");
        Err(error)
      }
      None => Ok(()),
    }
  })?
}
