//! module: plugins::upstream::client
//! responsibility: construct and own configured upstream transport
//! pools
//! public operations: Upstream, forward, connect_for_tunnel,
//! UpstreamRegistry, new, get_upstream, contains_upstream, len,
//! tls_config, tracker, close_all
//! data entities: ScheduledClient, Upstream, UpstreamRegistry
//! tests: client_tests.rs

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
pub(crate) use runtime::Upstream;

#[cfg(test)]
use super::config::CertificateConfig;
use super::error::UpstreamError;
use crate::tracker::StreamTracker;

// Sub-modules organized by protocol
mod client_tls;
mod connect_request;
#[cfg(test)]
mod connect_request_tests;
mod connection_pools;
mod direct;
#[cfg(test)]
mod direct_tests;
mod dns_cache;
#[cfg(test)]
mod dns_cache_tests;
mod forward;
#[cfg(test)]
mod forward_tests;
mod http;
mod http1_framing;
#[cfg(test)]
mod http1_framing_tests;
mod http3;
#[cfg(test)]
mod http3_tests;
mod http_cache;
mod http_pool;
#[cfg(test)]
mod http_tests;
mod nodes;
#[cfg(test)]
mod nodes_tests;
mod observation;
#[cfg(test)]
mod observation_tests;
mod origin_connector;
#[cfg(test)]
mod origin_connector_tests;
pub(super) mod protocol;
mod proxy_auth;
#[cfg(test)]
mod proxy_auth_tests;
mod response;
#[cfg(test)]
mod response_tests;
mod retry_request;
mod runtime;
use connection_pools::ConnectionPool;
pub(crate) use connection_pools::ConnectionPools;
mod socks5;
#[cfg(test)]
mod socks5_tests;
mod tcp_connect;
#[cfg(test)]
mod tcp_connect_tests;
mod transport_factory;
mod transport_io;

// ============================================================================
// Upstream Registry
// ============================================================================

pub(crate) struct UpstreamRegistry {
  entries: HashMap<String, Rc<Upstream>>,
}

impl UpstreamRegistry {
  #[cfg(test)]
  pub(crate) fn new(
    upstreams: HashMap<String, super::config::Upstream>,
    certificates: Option<&CertificateConfig>,
    tracker: Rc<StreamTracker>,
  ) -> Result<Self> {
    let config = super::config::connection_pool::ConnectionPoolConfig {
      name: "default".into(),
      certificates: certificates.cloned(),
      ..Default::default()
    };
    let pools = ConnectionPools::new(HashMap::from([(
      "default".into(),
      config,
    )]))?;
    Self::with_connection_pools(upstreams, tracker, pools)
  }

  pub(crate) fn with_connection_pools(
    upstreams: HashMap<String, super::config::Upstream>,
    tracker: Rc<StreamTracker>,
    connection_pools: Arc<ConnectionPools>,
  ) -> Result<Self> {
    let mut entries: HashMap<String, Rc<Upstream>> = HashMap::new();

    for (name, config) in upstreams {
      entries.insert(
        name.clone(),
        Rc::new(Upstream::new(
          config,
          tracker.clone(),
          connection_pools.clone(),
          name.clone(),
        )),
      );
    }

    Ok(Self { entries })
  }

  pub(crate) fn get_upstream(
    &self,
    name: &str,
  ) -> Result<Rc<Upstream>, UpstreamError> {
    self
      .entries
      .get(name)
      .ok_or_else(|| {
        UpstreamError::ProxyInternalError(format!(
          "upstream '{name}' not found"
        ))
      })
      .cloned()
  }

  pub(crate) fn contains_upstream(&self, name: &str) -> bool {
    self.entries.contains_key(name)
  }

  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  pub(crate) fn close_all(&self) {
    for upstream in self.entries.values() {
      upstream.close();
    }
  }
}
