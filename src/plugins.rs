use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::Result;

use super::plugin;
mod listener_hyper;
mod service_echo;
mod service_http3_upstream;

pub struct PluginManager {
  service_facories:
    HashMap<&'static str, Box<dyn plugin::ServiceFactory>>,
  listener_facories:
    HashMap<&'static str, Box<dyn plugin::ListenerFactory>>,
}

impl PluginManager {
  fn new() -> Self {
    let mut plugin_manager = PluginManager {
      service_facories: HashMap::new(),
      listener_facories: HashMap::new(),
    };

    let plugin = service_http3_upstream::create_plugin();
    plugin_manager.service_facories.extend(plugin.service_factories());

    let plugin = service_echo::create_plugin();
    plugin_manager.service_facories.extend(plugin.service_factories());

    let plugin = listener_hyper::create_plugin();
    plugin_manager
      .listener_facories
      .extend(plugin.listener_factories());

    plugin_manager
  }

  pub fn create_service(
    &self,
    kind: &str,
    args: plugin::SerializedArgs,
  ) -> Result<plugin::Service> {
    let fac = self.service_facories.get(kind).unwrap(); // TODO:
    fac(args)
  }

  pub fn create_listener(
    &self,
    kind: &str,
    args: plugin::SerializedArgs,
    service: plugin::Service,
  ) -> Result<(plugin::Listener, plugin::ListenerCloser)> {
    let fac = self.listener_facories.get(kind).unwrap(); // TODO:
    fac(args, service)
  }

  pub fn global() -> &'static LazyLock<PluginManager> {
    static PLUGIN_MANAGER: LazyLock<PluginManager> =
      LazyLock::new(|| PluginManager::new());
    &PLUGIN_MANAGER
  }
}
