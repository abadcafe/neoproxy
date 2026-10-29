//! module: e2b
//! responsibility: construct process-shared E2B sandbox policy layers
//! public operations: SharedPolicies::{new}, create_plugin,
//! create_shared_plugin, plugin_name data entities: SharedPolicies,
//! PluginConfig, LayerConfig, E2bPlugin tests: e2b_tests.rs,
//! test_e2b_policy.py
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;

use crate::config::SerializedArgs;
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer};
mod cache;
#[cfg(test)]
mod cache_tests;
mod fetch;
#[cfg(test)]
mod fetch_tests;
mod layer;
mod policy;
#[cfg(test)]
mod policy_tests;
mod proxy;
#[cfg(test)]
mod proxy_tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginConfig {
  policy_api_url: String,
  #[serde(default = "api_timeout", with = "humantime_serde")]
  policy_api_timeout: Duration,
}
fn api_timeout() -> Duration {
  Duration::from_secs(5)
}
fn fallback_ttl() -> Duration {
  Duration::from_secs(60)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerConfig {
  #[serde(default = "fallback_ttl", with = "humantime_serde")]
  policy_fallback_ttl: Duration,
  default_policy: serde_json::Value,
}

pub(crate) struct SharedPolicies {
  source: Arc<fetch::Api>,
  caches: Mutex<HashMap<String, Arc<cache::Cache>>>,
}
impl SharedPolicies {
  pub(crate) fn new(args: &SerializedArgs) -> Result<Arc<Self>> {
    let config: PluginConfig = serde_yaml::from_value(args.clone())?;
    Ok(Arc::new(Self {
      source: Arc::new(fetch::Api::new(
        &config.policy_api_url,
        config.policy_api_timeout,
      )?),
      caches: Mutex::new(HashMap::new()),
    }))
  }

  fn build_layer(&self, args: SerializedArgs) -> Result<Layer> {
    let config: LayerConfig = serde_yaml::from_value(args)?;
    anyhow::ensure!(
      !config.policy_fallback_ttl.is_zero()
        && tokio::time::Instant::now()
          .checked_add(config.policy_fallback_ttl)
          .is_some(),
      "policy_fallback_ttl must be positive and finite"
    );
    let key = serde_json::to_string(&(
      config.policy_fallback_ttl,
      &config.default_policy,
    ))?;
    let mut caches =
      self.caches.lock().expect("policy registry poisoned");
    let cache = match caches.get(&key) {
      Some(cache) => cache.clone(),
      None => {
        let default =
          Arc::new(policy::Policy::parse(config.default_policy)?);
        let cache = Arc::new(cache::Cache::new(
          self.source.clone(),
          default,
          config.policy_fallback_ttl,
        ));
        caches.insert(key, cache.clone());
        cache
      }
    };
    Ok(Layer::new(layer::PolicyLayer::new(cache)))
  }
}
struct E2bPlugin {
  builder: Box<dyn BuildLayer>,
}
impl Plugin for E2bPlugin {
  fn layer_builder(&self, name: &str) -> Option<&dyn BuildLayer> {
    (name == "sandbox_network_policy").then_some(self.builder.as_ref())
  }
}
pub(crate) fn plugin_name() -> &'static str {
  "e2b"
}
pub(crate) fn create_plugin(
  args: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  create_shared_plugin(SharedPolicies::new(
    args
      .ok_or_else(|| anyhow::anyhow!("e2b requires policy_api_url"))?,
  )?)
}
pub(crate) fn create_shared_plugin(
  shared: Arc<SharedPolicies>,
) -> Result<Box<dyn Plugin>> {
  Ok(Box::new(E2bPlugin {
    builder: Box::new(move |args| shared.build_layer(args)),
  }))
}
