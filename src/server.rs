#![allow(clippy::borrowed_box)]
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::{runtime, sync, task, time::timeout};
use tracing::{info, warn};

use crate::config::Config;
use crate::config_validator::parse_kind;
use crate::listeners::ListenerBuilderSet;
use crate::plugin;
use crate::plugins::PluginBuilderSet;

/// Timeout for Phase 1: Listener shutdown.
/// All listeners share this single timeout duration.
pub const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeout for Phase 2: Service/Plugin uninstall.
/// All plugins share this single timeout duration.
pub const PLUGIN_UNINSTALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Context for executing the two-phase graceful shutdown.
///
/// This struct encapsulates the shutdown logic and can be tested
/// independently of Config::global().
pub struct ShutdownContext {
  /// Listeners to be stopped in Phase 1
  pub listeners: Vec<Rc<plugin::Listener>>,
  /// Listener futures currently running
  pub listener_join_set: task::JoinSet<Result<()>>,
  /// Plugins to be uninstalled in Phase 2
  pub plugins: PluginSet,
}

impl ShutdownContext {
  /// Create a new empty shutdown context.
  pub fn new() -> Self {
    Self {
      listeners: Vec::new(),
      listener_join_set: task::JoinSet::new(),
      plugins: PluginSet::new(),
    }
  }

  /// Execute the two-phase graceful shutdown.
  ///
  /// # Phase 1: Shutdown all listeners
  /// - Call stop() on all listeners simultaneously
  /// - Wait for all listener.start() futures to complete with timeout
  /// - Timeout: abort remaining tasks
  ///
  /// # Phase 2: Uninstall all plugins
  /// - Call uninstall() on all plugins simultaneously
  /// - Wait for all uninstall futures to complete with timeout
  /// - Timeout: abort remaining tasks
  pub async fn graceful_shutdown(&mut self) {
    // Phase 1: Shutdown all listeners
    self.shutdown_listeners().await;

    // Phase 2: Uninstall all plugins
    self.uninstall_plugins().await;

    info!("shutdown completed");
  }

  /// Phase 1: Shutdown all listeners with timeout.
  async fn shutdown_listeners(&mut self) {
    // Call stop() on all listeners simultaneously
    for l in &self.listeners {
      l.stop();
    }

    let listener_count = self.listener_join_set.len();
    let listener_result = timeout(LISTENER_SHUTDOWN_TIMEOUT, async {
      while let Some(res) = self.listener_join_set.join_next().await {
        if let Err(e) = res {
          warn!("listener join error: {e}");
        } else if let Ok(Err(e)) = res {
          warn!("listener error: {e}");
        }
      }
    })
    .await;

    if listener_result.is_err() {
      let remaining = self.listener_join_set.len();
      warn!(
        "listener shutdown timeout ({:?}) expired, aborting {} \
         remaining listeners ({} total)",
        LISTENER_SHUTDOWN_TIMEOUT, remaining, listener_count
      );
      self.listener_join_set.abort_all();
      // Wait for aborted tasks to be cleaned up
      while self.listener_join_set.join_next().await.is_some() {}
    }
  }

  /// Phase 2: Uninstall all plugins with timeout.
  async fn uninstall_plugins(&mut self) {
    let mut plugin_uninstall_set = self.plugins.uninstall_all();
    let plugin_count = plugin_uninstall_set.len();

    let plugin_result = timeout(PLUGIN_UNINSTALL_TIMEOUT, async {
      while let Some(res) = plugin_uninstall_set.join_next().await {
        if let Err(e) = res {
          warn!("plugin uninstall join error: {e}");
        }
      }
    })
    .await;

    if plugin_result.is_err() {
      let remaining = plugin_uninstall_set.len();
      warn!(
        "plugin uninstall timeout ({:?}) expired, aborting {} \
         remaining plugins ({} total)",
        PLUGIN_UNINSTALL_TIMEOUT, remaining, plugin_count
      );
      plugin_uninstall_set.abort_all();
      // Wait for aborted tasks to be cleaned up
      while plugin_uninstall_set.join_next().await.is_some() {}
    }
  }
}

/// A set of plugins that can be managed and uninstalled together.
pub struct PluginSet {
  plugins: HashMap<&'static str, Box<dyn plugin::Plugin>>,
}

impl PluginSet {
  /// Create a new empty plugin set.
  pub fn new() -> PluginSet {
    Self { plugins: HashMap::new() }
  }

  /// Get or create a plugin by name.
  ///
  /// If the plugin already exists in the set, returns a reference to it.
  /// If not, creates it using the global plugin builder registry.
  pub fn get_or_create_plugin(
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

  /// Get mutable access to the plugins map for testing.
  #[cfg(test)]
  pub fn plugins_mut(
    &mut self,
  ) -> &mut HashMap<&'static str, Box<dyn plugin::Plugin>> {
    &mut self.plugins
  }

  /// Call uninstall() on all plugins and collect the futures.
  /// Returns a JoinSet containing all uninstall futures.
  pub fn uninstall_all(&mut self) -> task::JoinSet<()> {
    let mut join_set = task::JoinSet::new();
    for plugin in self.plugins.values_mut() {
      let fut = plugin.uninstall();
      join_set.spawn_local(fut);
    }
    join_set
  }
}

async fn server_thread_main(shutdown: Arc<sync::Notify>) -> Result<()> {
  let mut ctx = ShutdownContext::new();
  let mut services = HashMap::new();

  // Build all services
  // Note: Config validation ensures all plugins and builders exist
  for sc in Config::global().services.iter() {
    let (plugin_name, service_name) =
      parse_kind(&sc.kind, "service").expect("kind format validated");
    let plugin = ctx
      .plugins
      .get_or_create_plugin(plugin_name)
      .expect("plugin should exist (validated)");

    let builder = plugin
      .service_builder(service_name)
      .expect("service builder should exist (validated)");

    let svc = builder(sc.args.clone())?;
    services.insert(sc.name.as_str(), svc);
  }
  info!("created services:\n{services:#?}\n");

  // Build all listeners
  // Note: Config validation ensures all builders, and service
  // references exist
  for sc in &Config::global().servers {
    for lc in &sc.listeners {
      let builder = ListenerBuilderSet::global()
        .listener_builder(&lc.kind)
        .expect("listener builder should exist (validated)");

      let l: plugin::Listener = builder(
        lc.args.clone(),
        services
          .get(sc.service.as_str())
          .expect("service should exist (validated)")
          .clone(),
      )?;
      let l = Rc::new(l);
      ctx.listeners.push(Rc::clone(&l));
      ctx.listener_join_set.spawn_local(l.start());
    }
  }

  // Wait for shutdown signal
  shutdown.notified().await;

  // Execute graceful shutdown
  ctx.graceful_shutdown().await;

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
  use std::cell::Cell;
  use std::future::Future;
  use std::pin::Pin;
  use std::rc::Rc;

  // ============== PluginSet Tests ==============

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
    let result = plugin_set.get_or_create_plugin("connect_tcp");
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

  // ============== Timeout Constants Tests ==============

  #[test]
  fn test_listener_shutdown_timeout_is_3_seconds() {
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT, Duration::from_secs(3));
  }

  #[test]
  fn test_plugin_uninstall_timeout_is_5_seconds() {
    assert_eq!(PLUGIN_UNINSTALL_TIMEOUT, Duration::from_secs(5));
  }

  // ============== ShutdownContext Tests ==============

  #[test]
  fn test_shutdown_context_new() {
    let ctx = ShutdownContext::new();
    assert!(ctx.listeners.is_empty());
    assert_eq!(ctx.listener_join_set.len(), 0);
    assert!(ctx.plugins.plugins.is_empty());
  }

  #[tokio::test]
  async fn test_graceful_shutdown_empty() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ctx = ShutdownContext::new();
        // Should complete immediately with no listeners or plugins
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          ctx.graceful_shutdown(),
        )
        .await;
        assert!(result.is_ok());
      })
      .await;
  }

  /// A mock listener for testing that completes immediately after stop.
  struct MockListener {
    stopped: Rc<Cell<bool>>,
    shutdown_handle: plugin::ShutdownHandle,
  }

  impl MockListener {
    fn new(stopped: Rc<Cell<bool>>) -> Self {
      Self { stopped, shutdown_handle: plugin::ShutdownHandle::new() }
    }
  }

  impl plugin::Listening for MockListener {
    fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
      let stopped = self.stopped.clone();
      let shutdown = self.shutdown_handle.clone();
      Box::pin(async move {
        // Wait for stop signal
        shutdown.notified().await;
        stopped.set(true);
        Ok(())
      })
    }

    fn stop(&self) {
      self.shutdown_handle.shutdown();
    }
  }

  #[tokio::test]
  async fn test_shutdown_context_with_mock_listener() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let stopped = Rc::new(Cell::new(false));
        let listener = MockListener::new(stopped.clone());

        let mut ctx = ShutdownContext::new();
        let l = Rc::new(plugin::Listener::new(listener));
        ctx.listeners.push(Rc::clone(&l));
        ctx.listener_join_set.spawn_local(l.start());

        // Give the listener time to start
        tokio::task::yield_now().await;
        assert!(!stopped.get());

        // Execute shutdown
        ctx.graceful_shutdown().await;

        // Listener should have been stopped
        assert!(stopped.get());
      })
      .await;
  }

  /// A mock listener that never completes (for timeout testing).
  struct HangingListener {
    shutdown_handle: plugin::ShutdownHandle,
  }

  impl HangingListener {
    fn new() -> Self {
      Self { shutdown_handle: plugin::ShutdownHandle::new() }
    }
  }

  impl plugin::Listening for HangingListener {
    fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
      let shutdown = self.shutdown_handle.clone();
      Box::pin(async move {
        // Wait for stop signal but then hang
        shutdown.notified().await;
        // This will hang forever
        std::future::pending::<()>().await;
        Ok(())
      })
    }

    fn stop(&self) {
      self.shutdown_handle.shutdown();
    }
  }

  #[tokio::test]
  async fn test_shutdown_context_listener_timeout() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let listener = HangingListener::new();

        let mut ctx = ShutdownContext::new();
        let l = Rc::new(plugin::Listener::new(listener));
        ctx.listeners.push(Rc::clone(&l));
        ctx.listener_join_set.spawn_local(l.start());

        // Give the listener time to start
        tokio::task::yield_now().await;

        // Execute shutdown with a short timeout
        // The listener hangs, so this should timeout and abort
        let result = tokio::time::timeout(
          LISTENER_SHUTDOWN_TIMEOUT + Duration::from_millis(100),
          ctx.graceful_shutdown(),
        )
        .await;

        // Should complete within the timeout (after aborting)
        assert!(
          result.is_ok(),
          "shutdown should complete after timeout abort"
        );
      })
      .await;
  }

  /// Test that multiple listeners are stopped in parallel.
  /// This test verifies that all listeners receive stop() calls
  /// simultaneously and complete together.
  #[tokio::test]
  async fn test_shutdown_context_multiple_listeners_parallel_stop() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        // Create multiple listeners with independent stop flags
        let stopped1 = Rc::new(Cell::new(false));
        let stopped2 = Rc::new(Cell::new(false));
        let stopped3 = Rc::new(Cell::new(false));

        let listener1 = MockListener::new(stopped1.clone());
        let listener2 = MockListener::new(stopped2.clone());
        let listener3 = MockListener::new(stopped3.clone());

        let mut ctx = ShutdownContext::new();

        let l1 = Rc::new(plugin::Listener::new(listener1));
        let l2 = Rc::new(plugin::Listener::new(listener2));
        let l3 = Rc::new(plugin::Listener::new(listener3));

        ctx.listeners.push(Rc::clone(&l1));
        ctx.listeners.push(Rc::clone(&l2));
        ctx.listeners.push(Rc::clone(&l3));

        ctx.listener_join_set.spawn_local(l1.start());
        ctx.listener_join_set.spawn_local(l2.start());
        ctx.listener_join_set.spawn_local(l3.start());

        // Give listeners time to start
        tokio::task::yield_now().await;

        // Verify none are stopped yet
        assert!(!stopped1.get());
        assert!(!stopped2.get());
        assert!(!stopped3.get());

        // Execute shutdown
        ctx.graceful_shutdown().await;

        // All listeners should have been stopped
        assert!(stopped1.get(), "listener 1 should have been stopped");
        assert!(stopped2.get(), "listener 2 should have been stopped");
        assert!(stopped3.get(), "listener 3 should have been stopped");
      })
      .await;
  }

  /// Test that multiple hanging listeners timeout and abort together.
  #[tokio::test]
  async fn test_shutdown_context_multiple_hanging_listeners_timeout() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut ctx = ShutdownContext::new();

        // Add multiple hanging listeners
        for _ in 0..3 {
          let listener = HangingListener::new();
          let l = Rc::new(plugin::Listener::new(listener));
          ctx.listeners.push(Rc::clone(&l));
          ctx.listener_join_set.spawn_local(l.start());
        }

        // Give listeners time to start
        tokio::task::yield_now().await;
        assert_eq!(ctx.listener_join_set.len(), 3);

        // Execute shutdown - should timeout and abort all
        let result = tokio::time::timeout(
          LISTENER_SHUTDOWN_TIMEOUT + Duration::from_millis(100),
          ctx.graceful_shutdown(),
        )
        .await;

        // Should complete within the timeout (after aborting)
        assert!(
          result.is_ok(),
          "shutdown should complete after timeout abort"
        );

        // All listeners should be cleaned up
        assert_eq!(
          ctx.listener_join_set.len(),
          0,
          "all listeners should be cleaned up after abort"
        );
      })
      .await;
  }

  /// Test that mixed listeners (some completing, some hanging) work correctly.
  #[tokio::test]
  async fn test_shutdown_context_mixed_listeners() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let stopped = Rc::new(Cell::new(false));

        let mut ctx = ShutdownContext::new();

        // One normal listener
        let normal_listener = MockListener::new(stopped.clone());
        let l1 = Rc::new(plugin::Listener::new(normal_listener));
        ctx.listeners.push(Rc::clone(&l1));
        ctx.listener_join_set.spawn_local(l1.start());

        // One hanging listener
        let hanging_listener = HangingListener::new();
        let l2 = Rc::new(plugin::Listener::new(hanging_listener));
        ctx.listeners.push(Rc::clone(&l2));
        ctx.listener_join_set.spawn_local(l2.start());

        // Give listeners time to start
        tokio::task::yield_now().await;
        assert_eq!(ctx.listener_join_set.len(), 2);

        // Execute shutdown
        let result = tokio::time::timeout(
          LISTENER_SHUTDOWN_TIMEOUT + Duration::from_millis(100),
          ctx.graceful_shutdown(),
        )
        .await;

        // Should complete within the timeout (after aborting hanging listener)
        assert!(
          result.is_ok(),
          "shutdown should complete after timeout abort"
        );

        // Both listeners should be cleaned up
        assert_eq!(ctx.listener_join_set.len(), 0);

        // Normal listener should have been stopped properly
        assert!(stopped.get());
      })
      .await;
  }

  // ============== PluginSet::uninstall_all Tests ==============

  /// A test plugin that tracks if uninstall was called.
  struct TestUninstallPlugin {
    uninstalled: Rc<Cell<bool>>,
  }

  impl TestUninstallPlugin {
    fn new(flag: Rc<Cell<bool>>) -> Self {
      Self { uninstalled: flag }
    }
  }

  impl plugin::Plugin for TestUninstallPlugin {
    fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
      let flag = self.uninstalled.clone();
      Box::pin(async move {
        flag.set(true);
      })
    }
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_empty() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin_set = PluginSet::new();
        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 0);
        // Should complete immediately
        while join_set.join_next().await.is_some() {}
      })
      .await;
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_single_plugin() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let flag = Rc::new(Cell::new(false));
        let plugin = TestUninstallPlugin::new(flag.clone());

        let mut plugin_set = PluginSet::new();
        plugin_set.plugins_mut().insert("test", Box::new(plugin));

        assert!(!flag.get(), "uninstall should not be called yet");

        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 1);

        // Wait for uninstall to complete
        while join_set.join_next().await.is_some() {}

        assert!(flag.get(), "uninstall should have been called");
      })
      .await;
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_multiple_plugins() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let flag1 = Rc::new(Cell::new(false));
        let flag2 = Rc::new(Cell::new(false));
        let flag3 = Rc::new(Cell::new(false));

        let plugin1 = TestUninstallPlugin::new(flag1.clone());
        let plugin2 = TestUninstallPlugin::new(flag2.clone());
        let plugin3 = TestUninstallPlugin::new(flag3.clone());

        let mut plugin_set = PluginSet::new();
        plugin_set.plugins_mut().insert("test1", Box::new(plugin1));
        plugin_set.plugins_mut().insert("test2", Box::new(plugin2));
        plugin_set.plugins_mut().insert("test3", Box::new(plugin3));

        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 3);

        // Wait for all uninstalls to complete
        while join_set.join_next().await.is_some() {}

        assert!(
          flag1.get(),
          "plugin1 uninstall should have been called"
        );
        assert!(
          flag2.get(),
          "plugin2 uninstall should have been called"
        );
        assert!(
          flag3.get(),
          "plugin3 uninstall should have been called"
        );
      })
      .await;
  }

  /// A test plugin with a slow uninstall that respects cancellation.
  struct SlowUninstallPlugin {
    delay_ms: u64,
  }

  impl SlowUninstallPlugin {
    fn new(delay_ms: u64) -> Self {
      Self { delay_ms }
    }
  }

  impl plugin::Plugin for SlowUninstallPlugin {
    fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
      let delay = self.delay_ms;
      Box::pin(async move {
        tokio::time::sleep(Duration::from_millis(delay)).await;
      })
    }
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_slow_plugin() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = SlowUninstallPlugin::new(50);

        let mut plugin_set = PluginSet::new();
        plugin_set.plugins_mut().insert("slow", Box::new(plugin));

        let mut join_set = plugin_set.uninstall_all();

        // Should complete within reasonable time (100ms > 50ms delay)
        let result =
          tokio::time::timeout(Duration::from_millis(100), async {
            while join_set.join_next().await.is_some() {}
          })
          .await;
        assert!(result.is_ok(), "slow uninstall should complete");
      })
      .await;
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_can_be_aborted() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = SlowUninstallPlugin::new(10000); // Very slow

        let mut plugin_set = PluginSet::new();
        plugin_set.plugins_mut().insert("slow", Box::new(plugin));

        let mut join_set = plugin_set.uninstall_all();

        // Abort after a short time
        tokio::time::sleep(Duration::from_millis(10)).await;
        join_set.abort_all();

        // Should complete quickly after abort
        let result =
          tokio::time::timeout(Duration::from_millis(100), async {
            while join_set.join_next().await.is_some() {}
          })
          .await;
        assert!(
          result.is_ok(),
          "aborted uninstall should complete quickly"
        );
      })
      .await;
  }

  // ============== Real Plugin uninstall_all Tests ==============

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_with_echo_plugin() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin_set = PluginSet::new();
        let _ = plugin_set.get_or_create_plugin("echo");

        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 1);

        // Echo plugin's default uninstall should complete immediately
        let result =
          tokio::time::timeout(Duration::from_millis(100), async {
            while join_set.join_next().await.is_some() {}
          })
          .await;
        assert!(result.is_ok());
      })
      .await;
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_with_connect_tcp_plugin() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin_set = PluginSet::new();
        let _ = plugin_set.get_or_create_plugin("connect_tcp");

        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 1);

        // ConnectTcp plugin's uninstall should complete quickly
        // when no tunnels are active
        let result =
          tokio::time::timeout(Duration::from_millis(100), async {
            while join_set.join_next().await.is_some() {}
          })
          .await;
        assert!(result.is_ok());
      })
      .await;
  }

  #[tokio::test]
  async fn test_plugin_set_uninstall_all_with_multiple_real_plugins() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin_set = PluginSet::new();
        let _ = plugin_set.get_or_create_plugin("echo");
        let _ = plugin_set.get_or_create_plugin("connect_tcp");

        let mut join_set = plugin_set.uninstall_all();
        assert_eq!(join_set.len(), 2);

        // Both plugins should uninstall quickly
        let result =
          tokio::time::timeout(Duration::from_millis(100), async {
            while join_set.join_next().await.is_some() {}
          })
          .await;
        assert!(result.is_ok());
      })
      .await;
  }

  #[tokio::test]
  async fn test_shutdown_context_with_plugin_uninstall() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let flag = Rc::new(Cell::new(false));
        let plugin = TestUninstallPlugin::new(flag.clone());

        let mut ctx = ShutdownContext::new();
        ctx.plugins.plugins_mut().insert("test", Box::new(plugin));

        assert!(!flag.get());

        ctx.graceful_shutdown().await;

        assert!(flag.get(), "plugin uninstall should have been called");
      })
      .await;
  }

  /// A plugin that never completes uninstall (for timeout testing).
  struct HangingUninstallPlugin;

  impl plugin::Plugin for HangingUninstallPlugin {
    fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
      Box::pin(async {
        // This will hang forever
        std::future::pending::<()>().await;
      })
    }
  }

  #[tokio::test]
  async fn test_shutdown_context_plugin_uninstall_timeout() {
    let local_set = task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = HangingUninstallPlugin;

        let mut ctx = ShutdownContext::new();
        ctx.plugins.plugins_mut().insert("hanging", Box::new(plugin));

        // Execute shutdown with a short timeout
        // The plugin uninstall hangs, so this should timeout and abort
        let result = tokio::time::timeout(
          PLUGIN_UNINSTALL_TIMEOUT + Duration::from_millis(100),
          ctx.graceful_shutdown(),
        )
        .await;

        // Should complete within the timeout (after aborting)
        assert!(
          result.is_ok(),
          "shutdown should complete after timeout abort"
        );
      })
      .await;
  }

  // ============== server_thread Tests ==============

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

  #[test]
  fn test_sync_notify_notify_waiters() {
    let notify = Arc::new(sync::Notify::new());
    let notify_clone = notify.clone();

    // notify_waiters() should not block if no one is waiting
    notify.notify_waiters();
    drop(notify_clone);
  }

  #[test]
  fn test_listener_builder_set_global() {
    let listener_builder =
      ListenerBuilderSet::global().listener_builder("hyper.listener");
    assert!(listener_builder.is_some());
  }

  #[test]
  fn test_listener_builder_set_nonexistent() {
    let listener_builder =
      ListenerBuilderSet::global().listener_builder("nonexistent");
    assert!(listener_builder.is_none());
  }
}
