use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{Result, anyhow};

use crate::plugin;

mod connect_tcp;
mod echo;
mod http3_chain;
mod hyper;
mod utils;

pub struct PluginBuilderSet {
  builders: HashMap<&'static str, Box<dyn plugin::BuildPlugin>>,
}

impl PluginBuilderSet {
  fn new() -> Self {
    let mut plugin_manager = Self { builders: HashMap::new() };
    let builders = &mut plugin_manager.builders;

    builders.insert(
      connect_tcp::plugin_name(),
      Box::new(connect_tcp::create_plugin),
    );
    builders.insert(echo::plugin_name(), Box::new(echo::create_plugin));
    builders
      .insert(hyper::plugin_name(), Box::new(hyper::create_plugin));

    plugin_manager
  }

  pub fn plugin_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildPlugin>> {
    self.builders.get(name)
  }

  pub fn global() -> &'static LazyLock<PluginBuilderSet> {
    static PLUGIN_MANAGER: LazyLock<PluginBuilderSet> =
      LazyLock::new(|| PluginBuilderSet::new());
    &PLUGIN_MANAGER
  }
}
