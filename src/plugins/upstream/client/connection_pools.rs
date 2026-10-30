//! module: connection_pools
//! responsibility: own process-wide upstream transport resources
//! public operations: ConnectionPools::{new,close,shutdown},
//! ConnectionPool data entities: ConnectionPools, ConnectionPool,
//! RuntimeOwner tests: global pool process contracts
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;

use super::http_cache::Cache;
use super::nodes::SharedNodes;
use crate::plugins::upstream::config::connection_pool::ConnectionPoolConfig;
use crate::retained_cache::RetainedCache;

pub(crate) struct ConnectionPool {
  pub(super) http: Arc<Cache>,
  pub(super) https: Arc<Cache>,
  pub(super) h3_runtime: tokio::runtime::Handle,
  pub(super) h3: Arc<super::http3::Store>,
  tasks: Arc<crate::task_tracker::background::TaskTracker>,
  pub(super) dns: Arc<super::dns_cache::DnsCache>,
  pub(super) tls: Arc<rustls::ClientConfig>,
}
impl ConnectionPool {
  fn new(
    settings: ConnectionPoolConfig,
  ) -> anyhow::Result<(Arc<Self>, RuntimeOwner)> {
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
    let tasks =
      Arc::new(crate::task_tracker::background::TaskTracker::new());
    let owner =
      RuntimeOwner { runtime: Some(runtime), tasks: tasks.clone() };
    let handle =
      owner.runtime.as_ref().expect("new runtime").handle().clone();
    Ok((
      Arc::new(Self {
        http: Cache::new(
          config.http.max_idle_per_host,
          config.http.idle_timeout,
          settings.response_limits.limits(),
          tasks.clone(),
          handle.clone(),
        ),
        https: Cache::new(
          config.https.max_idle_per_host,
          config.https.idle_timeout,
          settings.response_limits.limits(),
          tasks.clone(),
          handle.clone(),
        ),
        h3_runtime: handle.clone(),
        h3: super::http3::Store::new(
          config.h3_connections,
          config.h3_idle_timeout,
          settings.response_limits.limits(),
          tasks.clone(),
        ),
        tasks,
        dns,
        tls,
      }),
      owner,
    ))
  }

  pub(crate) fn close(&self) {
    self.tasks.shutdown();
    self.http.close();
    self.https.close();
    self.h3.close();
  }
}
struct RuntimeOwner {
  runtime: Option<tokio::runtime::Runtime>,
  tasks: Arc<crate::task_tracker::background::TaskTracker>,
}
impl RuntimeOwner {
  fn shutdown(mut self) {
    if let Some(runtime) = self.runtime.take() {
      runtime.block_on(
        self
          .tasks
          .graceful_shutdown(crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT),
      );
      runtime
        .shutdown_timeout(crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT);
    }
  }
}
impl Drop for RuntimeOwner {
  fn drop(&mut self) {
    if let Some(runtime) = self.runtime.take() {
      runtime.shutdown_background();
    }
  }
}

/// Process-owned registry. Connection resources are isolated by name;
/// node scheduling remains shared within an upstream across pool
/// choices.
pub(crate) struct ConnectionPools {
  pools: HashMap<String, Arc<ConnectionPool>>,
  runtimes: Vec<RuntimeOwner>,
  nodes: Mutex<RetainedCache<(String, String), Arc<SharedNodes>>>,
}
impl ConnectionPools {
  pub(crate) fn new(
    configs: HashMap<String, ConnectionPoolConfig>,
  ) -> anyhow::Result<Arc<Self>> {
    let mut runtimes = Vec::new();
    let pools = configs
      .into_iter()
      .map(|(name, config)| {
        let (pool, runtime) = ConnectionPool::new(config)
          .with_context(|| format!("connection_pools[{name}]"))?;
        runtimes.push(runtime);
        Ok((name, pool))
      })
      .collect::<anyhow::Result<_>>()?;
    Ok(Arc::new(Self {
      pools,
      runtimes,
      nodes: Mutex::new(RetainedCache::new(1024)),
    }))
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
      .get_or_insert_with(
        key,
        || Arc::new(SharedNodes::default()),
        |nodes| Arc::strong_count(nodes) == 1,
      )
      .clone()
  }

  pub(crate) fn close(&self) {
    for pool in self.pools.values() {
      pool.close();
    }
  }

  /// Consume the process registry after all worker handles have left.
  pub(crate) fn shutdown(self: Arc<Self>) {
    let mut owner = Arc::try_unwrap(self).unwrap_or_else(|_| {
      panic!("pool shutdown requires joined workers")
    });
    owner.close();
    for runtime in owner.runtimes.drain(..) {
      runtime.shutdown();
    }
  }

  pub(crate) async fn monitor(&self) {
    let monitors: Vec<_> = self
      .pools
      .values()
      .map(|pool| Box::pin(pool.tasks.monitor()))
      .collect();
    if monitors.is_empty() {
      std::future::pending::<()>().await;
    }
    futures_util::future::select_all(monitors).await;
    unreachable!("connection pool monitoring never completes");
  }
}
