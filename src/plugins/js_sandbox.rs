pub mod config;
mod cpu_sandbox;
mod inject_ops;
mod mem_sandbox;
mod pool;
mod request;
mod sandbox;
mod service;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::plugins::js_sandbox::config::PluginConfig;
use crate::plugins::js_sandbox::pool::SandboxPool;
use crate::plugins::js_sandbox::service::SandboxService;
use crate::service::BuildService;

struct JsSandboxPlugin {
  service_builders: HashMap<&'static str, Box<dyn BuildService>>,
  pool: Arc<SandboxPool>,
}

impl JsSandboxPlugin {
  fn new(config: Option<&SerializedArgs>) -> Self {
    let plugin_config: PluginConfig = match config {
      Some(args) => serde_yaml::from_value(args.clone())
        .expect("failed to parse js_sandbox plugin config"),
      None => panic!("js_sandbox plugin requires configuration"),
    };

    let pool = Arc::new(SandboxPool::new(plugin_config.worker_threads));
    let config = Arc::new(plugin_config);

    let pool_clone = pool.clone();
    let config_clone = config.clone();
    let builder: Box<dyn BuildService> = Box::new(move |_args| {
      Ok(crate::service::Service::new(SandboxService::new(
        pool_clone.clone(),
        config_clone.clone(),
      )))
    });

    let service_builders = HashMap::from([("sandbox", builder)]);

    Self { service_builders, pool }
  }
}

impl Plugin for JsSandboxPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&dyn BuildService> {
    self.service_builders.get(name).map(|b| b.as_ref())
  }

  fn uninstall(
    &self,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> {
    let pool = self.pool.clone();
    Box::pin(async move {
      pool.shutdown();
      crate::plugins::js_sandbox::cpu_sandbox::stop_watchdog();
    })
  }
}

pub fn plugin_name() -> &'static str {
  "js_sandbox"
}

pub fn create_plugin(
  config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  Ok(Box::new(JsSandboxPlugin::new(config)))
}
