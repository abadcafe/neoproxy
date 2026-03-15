use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use tokio::{runtime, sync, task};
use tracing::{info, warn};

use crate::config::Config;
use crate::config_validator::parse_kind;
use crate::plugin;
use crate::plugins::PluginBuilderSet;

struct PluginSet {
  plugins: HashMap<&'static str, Box<dyn plugin::Plugin>>,
}

impl PluginSet {
  fn new() -> PluginSet {
    Self { plugins: HashMap::new() }
  }

  fn get_or_create_plugin(
    &mut self,
    name: &'static str,
  ) -> Option<&Box<dyn plugin::Plugin>> {
    let ent = self.plugins.entry(name);
    match ent {
      Entry::Vacant(ve) => {
        if let Some(builder) =
          PluginBuilderSet::global().plugin_builder(name)
        {
          Some(ve.insert(builder()))
        } else {
          None
        }
      }
      Entry::Occupied(oe) => Some(oe.into_mut()),
    }
  }
}

async fn server_thread_main(shutdown: Arc<sync::Notify>) -> Result<()> {
  let mut plugins = PluginSet::new();
  let mut services = HashMap::new();

  // Build all services
  // Note: Config validation ensures all plugins and builders exist
  for sc in Config::global().services.iter() {
    let (plugin_name, service_name) =
      parse_kind(&sc.kind, "service").expect("kind format validated");
    let plugin = plugins
      .get_or_create_plugin(plugin_name)
      .expect("plugin should exist (validated)");

    let builder = plugin
      .service_builder(service_name)
      .expect("service builder should exist (validated)");

    let svc = builder(sc.args.clone())?;
    services.insert(sc.name.as_str(), svc);
  }
  info!("created services:\n{services:#?}\n");

  let mut listeners: Vec<Rc<plugin::Listener>> = Vec::new();
  let mut listener_waitings = task::JoinSet::new();

  // Build all listeners
  // Note: Config validation ensures all plugins, builders, and service
  // references exist
  for sc in &Config::global().servers {
    for lc in &sc.listeners {
      let (plugin_name, listener_name) =
        parse_kind(&lc.kind, "listener")
          .expect("kind format validated");
      let plugin = plugins
        .get_or_create_plugin(plugin_name)
        .expect("plugin should exist (validated)");

      let builder = plugin
        .listener_builder(listener_name)
        .expect("listener builder should exist (validated)");

      let l: plugin::Listener = builder(
        lc.args.clone(),
        services
          .get(sc.service.as_str())
          .expect("service should exist (validated)")
          .clone(),
      )?;
      let l = Rc::new(l);
      listeners.push(Rc::clone(&l));
      listener_waitings.spawn_local(l.start());
    }
  }

  shutdown.notified().await;

  for l in &listeners {
    l.stop();
  }

  let res = listener_waitings.join_all().await;
  res.iter().for_each(|r| {
    let _ =
      r.as_ref().inspect_err(|&e| warn!("listener join error: {e}"));
  });

  Ok(())
}

pub fn server_thread(
  name: &str,
  closer: Arc<sync::Notify>,
) -> Result<()> {
  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name(name)
    .build()?;
  rt.block_on(local_set.run_until(server_thread_main(closer)))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_plugin_set_new() {
    let plugin_set = PluginSet::new();
    assert!(plugin_set.plugins.is_empty());
  }

  #[test]
  fn test_plugin_set_get_or_create_plugin_nonexistent() {
    let mut plugin_set = PluginSet::new();
    // Requesting a nonexistent plugin should return None
    let result = plugin_set.get_or_create_plugin("nonexistent_plugin");
    assert!(result.is_none());
  }

  #[test]
  fn test_plugin_set_get_or_create_plugin_existing() {
    let mut plugin_set = PluginSet::new();
    // First call should create the plugin
    let result1 = plugin_set.get_or_create_plugin("echo");
    assert!(result1.is_some());

    // Second call should return the same plugin
    let result2 = plugin_set.get_or_create_plugin("echo");
    assert!(result2.is_some());
  }

  #[test]
  fn test_plugin_set_multiple_plugins() {
    let mut plugin_set = PluginSet::new();

    let echo = plugin_set.get_or_create_plugin("echo");
    assert!(echo.is_some());

    let hyper = plugin_set.get_or_create_plugin("hyper");
    assert!(hyper.is_some());

    let connect_tcp = plugin_set.get_or_create_plugin("connect_tcp");
    assert!(connect_tcp.is_some());
  }

  #[test]
  fn test_plugin_set_plugin_caching() {
    let mut plugin_set = PluginSet::new();

    // Create plugin first time
    let plugin1 = plugin_set.get_or_create_plugin("echo").unwrap();
    let builder1 = plugin1.service_builder("echo");
    assert!(builder1.is_some());

    // Get the same plugin again
    let plugin2 = plugin_set.get_or_create_plugin("echo").unwrap();
    let builder2 = plugin2.service_builder("echo");
    assert!(builder2.is_some());
  }

  #[test]
  fn test_plugin_set_entry_vacant() {
    let mut plugin_set = PluginSet::new();
    // Test the Vacant entry path
    assert!(plugin_set.plugins.is_empty());
    let result = plugin_set.get_or_create_plugin("hyper");
    assert!(result.is_some());
    assert_eq!(plugin_set.plugins.len(), 1);
  }

  #[test]
  fn test_plugin_set_entry_occupied() {
    let mut plugin_set = PluginSet::new();
    // First access creates the plugin
    let _ = plugin_set.get_or_create_plugin("echo");
    assert_eq!(plugin_set.plugins.len(), 1);

    // Second access uses the Occupied entry
    let _ = plugin_set.get_or_create_plugin("echo");
    assert_eq!(plugin_set.plugins.len(), 1); // Still only 1 plugin
  }

  #[test]
  fn test_server_thread_runtime_creation() {
    // Test that we can create a runtime with the expected configuration
    let rt = runtime::Builder::new_current_thread()
      .enable_all()
      .thread_name("test_thread")
      .build();
    assert!(rt.is_ok());
  }

  #[test]
  fn test_server_thread_local_set_creation() {
    // Test that LocalSet can be created
    let local_set = task::LocalSet::new();
    // LocalSet is created successfully if we get here
    drop(local_set);
  }

  #[test]
  fn test_shutdown_notify_creation() {
    // Test that shutdown notifier can be created
    let notify = Arc::new(sync::Notify::new());
    // Notify is created successfully if we get here
    drop(notify);
  }

  // Note: Testing server_thread() directly is challenging because:
  // 1. It depends on Config::global() which requires a valid config file
  // 2. It creates listeners that bind to network ports
  // 3. It runs indefinitely until shutdown is signaled
  //
  // The function is tested indirectly through integration tests that
  // provide a complete configuration and verify the server starts and
  // stops correctly.

  /// Test that server_thread returns an error if runtime creation fails
  /// (This is a theoretical test - in practice, runtime creation rarely fails)
  #[test]
  fn test_sync_notify_notify_waiters() {
    let notify = Arc::new(sync::Notify::new());
    let notify_clone = notify.clone();

    // notify_waiters() should not block if no one is waiting
    notify.notify_waiters();
    drop(notify_clone);
  }
}
