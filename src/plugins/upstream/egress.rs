//! module: egress
//! responsibility: represent validated per-request outbound routes
//! public operations: Proxy::new, Route::{new,allows,proxy,remote_dns},
//! ProxyTls, DestinationPolicy::allows data entities: Proxy, ProxyTls,
//! Route tests: e2b/proxy_tests.rs, test_e2b_policy.py
use std::sync::Arc;

use anyhow::{Result, ensure};

#[derive(Clone, Debug)]
pub(crate) struct ProxyTls {
  pub(crate) server_name: String,
  pub(crate) config: Arc<rustls::ClientConfig>,
}

pub(crate) struct Proxy {
  pub(super) address: String,
  pub(super) user: Option<crate::config::UserCredential>,
  pub(super) tls: Option<ProxyTls>,
}
impl std::fmt::Debug for Proxy {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Proxy")
      .field("address", &self.address)
      .field("tls", &self.tls.is_some())
      .finish_non_exhaustive()
  }
}
impl Proxy {
  pub(crate) fn new(
    address: String,
    user: Option<crate::config::UserCredential>,
    tls: Option<ProxyTls>,
  ) -> Result<Self> {
    let authority = crate::http_authority::normalize(&address.parse()?)
      .map_err(|_| anyhow::anyhow!("invalid egressProxy address"))?;
    ensure!(
      authority.port_u16().is_some(),
      "egressProxy address requires a port"
    );
    Ok(Self { address: authority.to_string(), user, tls })
  }
}
/// Destination authorization belongs to the caller; DNS and actual
/// socket selection remain owned by the upstream connector.
pub(crate) trait DestinationPolicy: Send + Sync {
  fn allows(&self, host: &str, ip: std::net::IpAddr) -> bool;
}
#[derive(Clone)]
pub(crate) struct Route {
  policy: Arc<dyn DestinationPolicy>,
  proxy: Option<Arc<Proxy>>,
  remote_dns: bool,
}
impl Route {
  pub(crate) fn new(
    policy: Arc<dyn DestinationPolicy>,
    proxy: Option<Arc<Proxy>>,
    remote_dns: bool,
  ) -> Self {
    Self { policy, proxy, remote_dns }
  }

  pub(crate) fn allows(
    &self,
    host: &str,
    ip: std::net::IpAddr,
  ) -> bool {
    self.policy.allows(host, ip)
  }

  pub(crate) fn proxy(&self) -> Option<&Arc<Proxy>> {
    self.proxy.as_ref()
  }

  pub(crate) fn remote_dns(&self) -> bool {
    self.remote_dns
  }
}
