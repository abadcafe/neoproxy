//! module: connection_pools
//! responsibility: own process-wide upstream transport resources
//! public operations: ConnectionPools::{new,close,shutdown},
//! ConnectionPool data entities: ConnectionPools, ConnectionPool
//! tests: global pool process contracts
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;

use super::http_cache::Cache;
use super::nodes::SharedNodes;
use crate::plugins::upstream::config::connection_pool::ConnectionPoolConfig;

pub(crate) struct ConnectionPool {
  pub(super) http: Arc<Cache>,
  pub(super) https: Arc<Cache>,
  pub(super) h3_runtime: tokio::runtime::Handle,
  pub(super) h3: Arc<super::http3::Store>,
  runtime: Mutex<Option<tokio::runtime::Runtime>>,
  pub(super) dns: Arc<super::dns_cache::DnsCache>,
  pub(super) tls: Arc<rustls::ClientConfig>,
}
impl ConnectionPool {
  pub(crate) fn new(
    settings: ConnectionPoolConfig,
  ) -> anyhow::Result<Arc<Self>> {
    let config = settings.limits();
    let dns = Arc::new(super::dns_cache::DnsCache::new(
      settings.dns_servers.as_deref(),
      settings.dns_timeout(),
      settings
        .dns_refresh_retry_interval
        .unwrap_or(std::time::Duration::from_secs(30)),
    )?);
    let tls = super::client_tls::build(settings.certificates.as_ref())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(config.h3_threads)
      .thread_name("upstream-h3-io")
      .enable_all()
      .build()?;
    Ok(Arc::new(Self {
      http: Cache::new(
        config.http.max_idle_per_host,
        config.http.idle_timeout,
        settings.response_limits.limits(),
      ),
      https: Cache::new(
        config.https.max_idle_per_host,
        config.https.idle_timeout,
        settings.response_limits.limits(),
      ),
      h3_runtime: runtime.handle().clone(),
      h3: super::http3::Store::new(
        config.h3_connections,
        config.h3_idle_timeout,
        settings.response_limits.limits(),
      ),
      runtime: Mutex::new(Some(runtime)),
      dns,
      tls,
    }))
  }

  /// Called by the synchronous process owner after joining all workers.
  pub(crate) fn shutdown(&self) {
    self.close();
    if let Some(runtime) =
      self.runtime.lock().expect("runtime lock poisoned").take()
    {
      runtime
        .shutdown_timeout(crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT);
    }
  }

  pub(crate) fn close(&self) {
    self.http.close();
    self.https.close();
    self.h3.close();
  }
}
impl Drop for ConnectionPool {
  fn drop(&mut self) {
    if let Some(runtime) =
      self.runtime.get_mut().expect("runtime lock poisoned").take()
    {
      runtime.shutdown_background();
    }
  }
}

/// Process-owned registry. Connection resources are isolated by name;
/// node scheduling remains shared within an upstream across pool
/// choices.
pub(crate) struct ConnectionPools {
  pools: HashMap<String, Arc<ConnectionPool>>,
  nodes: Mutex<HashMap<(String, String), Arc<SharedNodes>>>,
}
impl ConnectionPools {
  pub(crate) fn new(
    configs: HashMap<String, ConnectionPoolConfig>,
  ) -> anyhow::Result<Arc<Self>> {
    let pools = configs
      .into_iter()
      .map(|(name, config)| {
        let pool = ConnectionPool::new(config)
          .with_context(|| format!("connection_pools[{name}]"))?;
        Ok((name, pool))
      })
      .collect::<anyhow::Result<_>>()?;
    Ok(Arc::new(Self { pools, nodes: Mutex::new(HashMap::new()) }))
  }

  pub(super) fn get(&self, name: &str) -> Arc<ConnectionPool> {
    self
      .pools
      .get(name)
      .expect("validated connection pool reference")
      .clone()
  }

  pub(super) fn nodes(
    &self,
    key: (String, String),
  ) -> Arc<SharedNodes> {
    self
      .nodes
      .lock()
      .expect("node registry poisoned")
      .entry(key)
      .or_default()
      .clone()
  }

  pub(crate) fn close(&self) {
    for pool in self.pools.values() {
      pool.close();
    }
  }

  pub(crate) fn shutdown(&self) {
    for pool in self.pools.values() {
      pool.shutdown();
    }
  }
}
