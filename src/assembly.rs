//! Build functions for assembling listeners from config.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use anyhow::Result;

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
pub fn build_service_with_layers(
  plugin_manager: &PluginManager,
  config: &Config,
  service_name: &str,
) -> Result<Service> {
  let sc = config
    .services
    .iter()
    .find(|s| s.name == service_name)
    .ok_or_else(|| {
      anyhow::anyhow!("service '{}' not found", service_name)
    })?;

  let mut service = plugin_manager.build_service(
    &sc.plugin_name,
    &sc.kind,
    sc.args.clone(),
  )?;

  // Wrap with layers (inner to outer)
  for layer_cfg in sc.layers.iter().rev() {
    let layer = plugin_manager.build_layer(
      &layer_cfg.plugin_name,
      &layer_cfg.kind,
      layer_cfg.args.clone(),
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
pub fn build_listeners(
  plugin_manager: &PluginManager,
  config: &Config,
  listener_manager: &ListenerManager,
) -> Result<Vec<Listener>> {
  // Build listener_name -> Vec<server::Server> mapping
  let mut listener_servers: HashMap<String, Vec<server::Server>> =
    HashMap::new();

  // Cache for built services (avoid rebuilding same service)
  let mut service_cache: HashMap<String, Service> = HashMap::new();

  for server_cfg in &config.servers {
    // Build service for this server (with caching)
    let service = match service_cache.entry(server_cfg.service.clone())
    {
      Entry::Occupied(e) => e.get().clone(),
      Entry::Vacant(e) => {
        let svc = build_service_with_layers(
          plugin_manager,
          config,
          &server_cfg.service,
        )?;
        e.insert(svc).clone()
      }
    };

    let entry = server::Server {
      hostnames: server_cfg.hostnames.clone(),
      service,
      service_name: server_cfg.service.clone(),
      tls: server_cfg.tls.clone(),
    };

    for listener_name in &server_cfg.listeners {
      listener_servers
        .entry(listener_name.clone())
        .or_default()
        .push(entry.clone());
    }
  }

  // Build Listener for each ListenerConfig
  let mut listeners = Vec::new();
  for lc in &config.listeners {
    let servers =
      listener_servers.get(&lc.name).cloned().unwrap_or_default();

    let listener = listener_manager.build_listener(
      &lc.kind,
      lc.addresses.clone(),
      lc.args.clone(),
      servers,
    )?;

    listeners.push(listener);
  }

  Ok(listeners)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll};

  use http_body_util::BodyExt;

  use super::*;
  use crate::config::{
    Layer as LayerConfig, ListenerConfig, SerializedArgs,
    Service as ServiceConfig,
  };
  use crate::listeners::ListenerManager;
  use crate::plugin::Plugin;
  use crate::service::{BuildLayer, Layer as ServiceLayer};

  // ========================================================================
  // Test helpers
  // ========================================================================

  /// A test layer that wraps requests and adds a marker header.
  struct TestMarkerLayer {
    name: String,
    counter: Arc<AtomicUsize>,
  }

  impl tower::Layer<crate::service::Service> for TestMarkerLayer {
    type Service = crate::service::Service;

    fn layer(&self, inner: crate::service::Service) -> Self::Service {
      let name = self.name.clone();
      let counter = self.counter.clone();
      counter.fetch_add(1, Ordering::SeqCst);
      crate::service::Service::new(TestMarkerMiddleware {
        inner,
        name,
        counter,
      })
    }
  }

  #[derive(Clone)]
  struct TestMarkerMiddleware {
    inner: crate::service::Service,
    name: String,
    counter: Arc<AtomicUsize>,
  }

  impl tower::Service<crate::http_utils::Request>
    for TestMarkerMiddleware
  {
    type Error = anyhow::Error;
    type Future = Pin<
      Box<dyn Future<Output = Result<crate::http_utils::Response>>>,
    >;
    type Response = crate::http_utils::Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
      self.inner.poll_ready(cx)
    }

    fn call(
      &mut self,
      mut req: crate::http_utils::Request,
    ) -> Self::Future {
      let name = self.name.clone();
      let counter = self.counter.clone();
      let mut inner = self.inner.clone();
      Box::pin(async move {
        counter.fetch_add(1, Ordering::SeqCst);
        // Add marker header to request extensions before forwarding
        req.extensions_mut().insert(name.clone());
        match inner.call(req).await {
          Ok(mut resp) => {
            let existing = resp
              .headers()
              .get("X-Layer-Order")
              .and_then(|v: &http::HeaderValue| v.to_str().ok())
              .unwrap_or("")
              .to_string();
            let new_val = if existing.is_empty() {
              name.clone()
            } else {
              format!("{};{}", existing, name)
            };
            resp.headers_mut().insert(
              "X-Layer-Order",
              http::HeaderValue::from_str(&new_val).unwrap(),
            );
            Ok(resp)
          }
          Err(e) => Err(e),
        }
      })
    }
  }

  /// A plugin that provides a test service and test layers for assembly
  /// tests.
  struct TestAssemblyPlugin {
    service_builders:
      HashMap<&'static str, Box<dyn crate::service::BuildService>>,
    layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
  }

  impl TestAssemblyPlugin {
    fn new() -> Self {
      let service_builders = HashMap::from([(
        "echo",
        Box::new(|_args| {
          // Create a service that returns 200 OK with empty body
          Ok(crate::service::Service::new(tower::service_fn(
            |_req: crate::http_utils::Request| {
              Box::pin(async {
                let body: crate::http_utils::ResponseBody =
                  http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|e: std::convert::Infallible| {
                      anyhow::anyhow!("{}", e)
                    })
                    .boxed_unsync();
                let mut resp = crate::http_utils::Response::new(body);
                *resp.status_mut() = http::StatusCode::OK;
                Ok::<_, anyhow::Error>(resp)
              })
                as std::pin::Pin<
                  Box<
                    dyn std::future::Future<
                        Output = anyhow::Result<
                          crate::http_utils::Response,
                        >,
                      >,
                  >,
                >
            },
          )))
        }) as Box<dyn crate::service::BuildService>,
      )]);
      let layer_builders = HashMap::new();
      Self { service_builders, layer_builders }
    }

    fn with_layer(
      mut self,
      name: &'static str,
      counter: Arc<AtomicUsize>,
    ) -> Self {
      let builder: Box<dyn BuildLayer> =
        Box::new(move |args: SerializedArgs| {
          let name_str = args
            .get("name")
            .and_then(|v: &serde_yaml::Value| v.as_str())
            .unwrap_or(name)
            .to_string();
          Ok(ServiceLayer::new(TestMarkerLayer {
            name: name_str,
            counter: counter.clone(),
          }))
        });
      self.layer_builders.insert(name, builder);
      self
    }
  }

  impl Plugin for TestAssemblyPlugin {
    fn service_builder(
      &self,
      name: &str,
    ) -> Option<&Box<dyn crate::service::BuildService>> {
      self.service_builders.get(name)
    }

    fn layer_builder(
      &self,
      name: &str,
    ) -> Option<&Box<dyn BuildLayer>> {
      self.layer_builders.get(name)
    }
  }

  fn make_test_plugin_manager() -> PluginManager {
    PluginManager::new()
  }

  fn make_test_plugin_manager_with_layers(
    counters: &[Arc<AtomicUsize>],
    names: &[&'static str],
  ) -> PluginManager {
    let mut pm = PluginManager::new();
    let mut plugin = TestAssemblyPlugin::new();
    for (name, counter) in names.iter().zip(counters.iter()) {
      plugin = plugin.with_layer(*name, counter.clone());
    }
    pm.plugins_mut().insert("test", Box::new(plugin));
    pm
  }

  // ========================================================================
  // CR-001: Existing tests (already present)
  // ========================================================================

  #[test]
  fn test_build_service_with_layers_not_found() {
    let pm = PluginManager::new();
    let config = Config::default();
    let result = build_service_with_layers(&pm, &config, "nonexistent");
    assert!(result.is_err());
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("service 'nonexistent' not found")
    );
  }

  #[test]
  fn test_build_listeners_empty_config() {
    let pm = PluginManager::new();
    let config = Config::default();
    let listener_manager = ListenerManager::new();
    let result = build_listeners(&pm, &config, &listener_manager);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
  }

  // ========================================================================
  // CR-002: Unknown listener kind error path
  // ========================================================================

  #[test]
  fn test_build_listeners_unknown_listener_kind() {
    let pm = make_test_plugin_manager();
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "test_listener".to_string(),
        kind: "nonexistent_kind".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        args: SerializedArgs::Null,
      }],
      servers: vec![],
      services: vec![],
      ..Default::default()
    };
    let listener_manager = ListenerManager::new();
    let result = build_listeners(&pm, &config, &listener_manager);
    match result {
      Err(e) => assert!(
        e.to_string()
          .contains("unknown listener kind 'nonexistent_kind'")
      ),
      Ok(_) => panic!("Expected error for unknown listener kind"),
    }
  }

  // ========================================================================
  // CR-003: Layer wrapping order (reverse order)
  // ========================================================================

  #[test]
  fn test_build_service_with_layers_reverse_order() {
    let counter_a = Arc::new(AtomicUsize::new(0));
    let counter_b = Arc::new(AtomicUsize::new(0));

    let pm = make_test_plugin_manager_with_layers(
      &[counter_a.clone(), counter_b.clone()],
      &["layer_a", "layer_b"],
    );

    let config = Config {
      services: vec![ServiceConfig {
        name: "test_svc".to_string(),
        plugin_name: "test".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![
          LayerConfig {
            plugin_name: "test".to_string(),
            kind: "layer_a".to_string(),
            args: SerializedArgs::Null,
          },
          LayerConfig {
            plugin_name: "test".to_string(),
            kind: "layer_b".to_string(),
            args: SerializedArgs::Null,
          },
        ],
      }],
      ..Default::default()
    };

    let result = build_service_with_layers(&pm, &config, "test_svc");
    assert!(result.is_ok());

    // Both layer counters should have been incremented (layers were
    // applied)
    assert_eq!(counter_a.load(Ordering::SeqCst), 1);
    assert_eq!(counter_b.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn test_build_service_with_layers_markers_in_reverse_order() {
    let counter_a = Arc::new(AtomicUsize::new(0));
    let counter_b = Arc::new(AtomicUsize::new(0));

    let pm = make_test_plugin_manager_with_layers(
      &[counter_a.clone(), counter_b.clone()],
      &["layer_a", "layer_b"],
    );

    let config = Config {
      services: vec![ServiceConfig {
        name: "test_svc".to_string(),
        plugin_name: "test".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![
          LayerConfig {
            plugin_name: "test".to_string(),
            kind: "layer_a".to_string(),
            args: SerializedArgs::Null,
          },
          LayerConfig {
            plugin_name: "test".to_string(),
            kind: "layer_b".to_string(),
            args: SerializedArgs::Null,
          },
        ],
      }],
      ..Default::default()
    };

    let service =
      build_service_with_layers(&pm, &config, "test_svc").unwrap();

    // Send a request through the layered service
    let body: crate::http_utils::RequestBody =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let req = http::Request::builder().body(body).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut svc = service;
    let resp =
      rt.block_on(tower::Service::call(&mut svc, req)).unwrap();

    // The marker headers should be in order: layer_b;layer_a
    // (layer_b is innermost, applied first, so its header is innermost
    // in the chain)
    let order = resp
      .headers()
      .get("X-Layer-Order")
      .and_then(|v: &http::HeaderValue| v.to_str().ok())
      .unwrap();
    assert_eq!(
      order, "layer_b;layer_a",
      "Layers should be applied in reverse config order: inner \
       (layer_b) first, then outer (layer_a)"
    );
  }

  // ========================================================================
  // CR-004: Service caching behavior
  // ========================================================================

  #[test]
  fn test_build_listeners_caches_service_across_servers() {
    let counter = Arc::new(AtomicUsize::new(0));
    let pm = make_test_plugin_manager_with_layers(
      &[counter.clone()],
      &["marker"],
    );

    let config = Config {
      services: vec![ServiceConfig {
        name: "shared_svc".to_string(),
        plugin_name: "test".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![LayerConfig {
          plugin_name: "test".to_string(),
          kind: "marker".to_string(),
          args: SerializedArgs::Null,
        }],
      }],
      listeners: vec![ListenerConfig {
        name: "main_listener".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        args: SerializedArgs::Null,
      }],
      servers: vec![
        crate::config::Server {
          name: "server1".to_string(),
          service: "shared_svc".to_string(),
          listeners: vec!["main_listener".to_string()],
          ..Default::default()
        },
        crate::config::Server {
          name: "server2".to_string(),
          service: "shared_svc".to_string(),
          listeners: vec!["main_listener".to_string()],
          ..Default::default()
        },
      ],
      ..Default::default()
    };

    let listener_manager = ListenerManager::new();
    let result = build_listeners(&pm, &config, &listener_manager);
    assert!(result.is_ok());

    // The service should have been built only once (cached),
    // so the layer's counter should only be incremented once.
    assert_eq!(
      counter.load(Ordering::SeqCst),
      1,
      "Service should be cached - layer applied only once for two \
       servers sharing same service"
    );
  }

  // ========================================================================
  // CR-005: build_service_with_layers success path
  // ========================================================================

  #[test]
  fn test_build_service_with_layers_success() {
    let pm = make_test_plugin_manager();
    let config = Config {
      services: vec![ServiceConfig {
        name: "my_echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![],
      }],
      ..Default::default()
    };

    let result = build_service_with_layers(&pm, &config, "my_echo");
    assert!(result.is_ok());
  }

  #[test]
  fn test_build_service_with_layers_not_found_in_plugin() {
    let pm = make_test_plugin_manager();
    let config = Config {
      services: vec![ServiceConfig {
        name: "bad_svc".to_string(),
        plugin_name: "echo".to_string(),
        kind: "nonexistent_service".to_string(),
        args: SerializedArgs::Null,
        layers: vec![],
      }],
      ..Default::default()
    };

    let result = build_service_with_layers(&pm, &config, "bad_svc");
    assert!(result.is_err());
    assert!(
      result.unwrap_err().to_string().contains("not found in plugin")
    );
  }

  #[test]
  fn test_build_service_with_layers_plugin_not_found() {
    let pm = PluginManager::new();
    let config = Config {
      services: vec![ServiceConfig {
        name: "svc".to_string(),
        plugin_name: "nonexistent_plugin".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![],
      }],
      ..Default::default()
    };

    let result = build_service_with_layers(&pm, &config, "svc");
    assert!(result.is_err());
    assert!(
      result
        .unwrap_err()
        .to_string()
        .contains("plugin 'nonexistent_plugin' not found")
    );
  }

  // ========================================================================
  // build_listeners with servers and listeners
  // ========================================================================

  #[test]
  fn test_build_listeners_with_servers() {
    let pm = make_test_plugin_manager();
    let config = Config {
      services: vec![ServiceConfig {
        name: "my_echo".to_string(),
        plugin_name: "echo".to_string(),
        kind: "echo".to_string(),
        args: SerializedArgs::Null,
        layers: vec![],
      }],
      listeners: vec![ListenerConfig {
        name: "main".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        args: SerializedArgs::Null,
      }],
      servers: vec![crate::config::Server {
        name: "s1".to_string(),
        service: "my_echo".to_string(),
        listeners: vec!["main".to_string()],
        ..Default::default()
      }],
      ..Default::default()
    };

    let listener_manager = ListenerManager::new();
    let result = build_listeners(&pm, &config, &listener_manager);
    assert!(result.is_ok());
    let listeners = result.unwrap();
    assert_eq!(listeners.len(), 1);
  }

  #[test]
  fn test_build_listeners_no_servers_referencing_listener() {
    let pm = make_test_plugin_manager();
    let config = Config {
      listeners: vec![ListenerConfig {
        name: "orphan".to_string(),
        kind: "http".to_string(),
        addresses: vec!["127.0.0.1:8080".to_string()],
        args: SerializedArgs::Null,
      }],
      servers: vec![],
      services: vec![],
      ..Default::default()
    };

    let listener_manager = ListenerManager::new();
    let result = build_listeners(&pm, &config, &listener_manager);
    // Should succeed with an empty server list for the listener
    assert!(result.is_ok());
    let listeners = result.unwrap();
    assert_eq!(listeners.len(), 1);
  }
}
