//! module: e2b
//! responsibility: construct process-shared E2B sandbox policy layers
//! public operations: SharedPolicies::{new}, create_plugin,
//! create_shared_plugin, plugin_name data entities: SharedPolicies,
//! PluginConfig, LayerConfig, E2bPlugin tests: e2b_tests.rs,
//! test_e2b_policy.py
use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
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
fn policy_cache_capacity() -> NonZeroUsize {
  NonZeroUsize::new(1024)
    .expect("positive default policy cache capacity")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerConfig {
  #[serde(default = "fallback_ttl", with = "humantime_serde")]
  policy_fallback_ttl: Duration,
  #[serde(default = "policy_cache_capacity")]
  policy_cache_capacity: NonZeroUsize,
  default_policy: serde_json::Value,
}

impl LayerConfig {
  fn parse(args: SerializedArgs) -> Result<(String, Self)> {
    let config: Self = serde_yaml::from_value(args)?;
    anyhow::ensure!(
      !config.policy_fallback_ttl.is_zero()
        && tokio::time::Instant::now()
          .checked_add(config.policy_fallback_ttl)
          .is_some(),
      "policy_fallback_ttl must be positive and finite"
    );
    let key = serde_json::to_string(&(
      config.policy_fallback_ttl,
      config.policy_cache_capacity,
      &config.default_policy,
    ))?;
    Ok((key, config))
  }

  fn cache(self, source: Arc<fetch::Api>) -> Result<Arc<cache::Cache>> {
    Ok(Arc::new(cache::Cache::new(
      source,
      Arc::new(policy::Policy::parse(self.default_policy)?),
      self.policy_fallback_ttl,
      self.policy_cache_capacity,
    )))
  }
}
fn source(args: &SerializedArgs) -> Result<Arc<fetch::Api>> {
  let config: PluginConfig = serde_yaml::from_value(args.clone())?;
  Ok(Arc::new(fetch::Api::new(
    &config.policy_api_url,
    config.policy_api_timeout,
  )?))
}

pub(crate) struct SharedPolicies {
  caches: HashMap<String, Arc<cache::Cache>>,
}
impl SharedPolicies {
  pub(crate) fn new<'a>(
    args: &SerializedArgs,
    layers: impl Iterator<Item = &'a SerializedArgs>,
  ) -> Result<Arc<Self>> {
    let source = source(args)?;
    let mut caches = HashMap::new();
    for args in layers {
      let (key, config) = LayerConfig::parse(args.clone())?;
      if let std::collections::hash_map::Entry::Vacant(entry) =
        caches.entry(key)
      {
        entry.insert(config.cache(source.clone())?);
      }
    }
    Ok(Arc::new(Self { caches }))
  }

  fn build_layer(&self, args: SerializedArgs) -> Result<Layer> {
    let (key, _) = LayerConfig::parse(args)?;
    let cache = self.caches.get(&key).ok_or_else(|| {
      anyhow::anyhow!(
        "policy layer was not prepared by the process owner"
      )
    })?;
    Ok(Layer::new(layer::PolicyLayer::new(cache.clone())))
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
  let source =
    source(args.ok_or_else(|| {
      anyhow::anyhow!("e2b requires policy_api_url")
    })?)?;
  // A standalone plugin has one local layer builder. Process workers
  // instead consume the immutable, prebuilt SharedPolicies directory.
  let caches =
    RefCell::new(HashMap::<String, Arc<cache::Cache>>::new());
  Ok(Box::new(E2bPlugin {
    builder: Box::new(move |args| {
      let (key, config) = LayerConfig::parse(args)?;
      let mut caches = caches.borrow_mut();
      let cache = match caches.entry(key) {
        std::collections::hash_map::Entry::Occupied(entry) => {
          entry.get().clone()
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
          entry.insert(config.cache(source.clone())?).clone()
        }
      };
      Ok(Layer::new(layer::PolicyLayer::new(cache)))
    }),
  }))
}

pub(crate) fn create_shared_plugin(
  shared: Arc<SharedPolicies>,
) -> Result<Box<dyn Plugin>> {
  Ok(Box::new(E2bPlugin {
    builder: Box::new(move |args| shared.build_layer(args)),
  }))
}
