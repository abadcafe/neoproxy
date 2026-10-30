//! module: dns_cache
//! responsibility: cache TTL-bound DNS answers and retain stale answers
//! on failure public operations: DnsCache::{new,resolve}
//! data entities: DnsCache, Entry
//! tests: dns_cache_tests.rs; test_upstream_nodes.py
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{
  ConnectionConfig, NameServerConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::observation::ConnectionObservation;
use crate::context::RequestContext;
use crate::plugins::upstream::error::UpstreamError;
use crate::retained_cache::RetainedCache;

struct Entry {
  addresses: Vec<IpAddr>,
  refresh: Instant,
  updated: Instant,
  error: Option<String>,
}
pub(super) struct DnsCache {
  resolver: TokioResolver,
  timeout: Duration,
  retry: Duration,
  entries: std::sync::Mutex<RetainedCache<String, Arc<Mutex<Entry>>>>,
}
impl DnsCache {
  pub(super) fn new(
    servers: Option<&[SocketAddr]>,
    timeout: Duration,
    retry: Duration,
  ) -> anyhow::Result<Self> {
    let mut builder = if let Some(servers) = servers {
      let servers = servers
        .iter()
        .map(|server| {
          let mut udp = ConnectionConfig::udp();
          udp.port = server.port();
          let mut tcp = ConnectionConfig::tcp();
          tcp.port = server.port();
          NameServerConfig::new(server.ip(), true, vec![udp, tcp])
        })
        .collect();
      Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
      )
    } else {
      Resolver::builder_tokio()?
    };
    builder.options_mut().timeout = timeout;
    builder.options_mut().attempts = 1;
    // The outer cache owns refresh and negative retry policy.
    builder.options_mut().cache_size = 0;
    Ok(Self {
      resolver: builder.build()?,
      timeout,
      retry,
      entries: std::sync::Mutex::new(RetainedCache::new(1024)),
    })
  }

  pub(super) async fn resolve(
    &self,
    authority: &str,
    ctx: Option<&RequestContext>,
  ) -> Result<Vec<SocketAddr>, UpstreamError> {
    let authority = authority
      .parse::<http::uri::Authority>()
      .map_err(|error| UpstreamError::DnsError(error.to_string()))?;
    let host =
      authority.host().trim_start_matches('[').trim_end_matches(']');
    let port = authority.port_u16().ok_or_else(|| {
      UpstreamError::DnsError("missing address port".into())
    })?;
    if let Ok(ip) = host.parse::<IpAddr>() {
      return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let slot = self
      .entries
      .lock()
      .expect("DNS cache poisoned")
      .get_or_insert_with(
        host.clone(),
        || {
          Arc::new(Mutex::new(Entry {
            addresses: Vec::new(),
            refresh: Instant::now(),
            updated: Instant::now(),
            error: None,
          }))
        },
        |slot| Arc::strong_count(slot) == 1,
      )
      .clone();
    let started = std::time::Instant::now();
    let waiting_since = Instant::now();
    let mut entry = slot.lock().await;
    let queried =
      Instant::now() >= entry.refresh && entry.updated <= waiting_since;
    if queried {
      let result = tokio::time::timeout(
        self.timeout,
        self.resolver.lookup_ip(format!("{host}.")),
      )
      .await;
      match result {
        Ok(Ok(lookup)) => {
          entry.addresses = lookup.iter().collect();
          entry.refresh = Instant::from_std(lookup.valid_until());
          entry.error = None;
        }
        error => {
          entry.error = Some(match error {
            Ok(Err(error)) => error.to_string(),
            Err(_) => "DNS resolve timed out".into(),
            Ok(Ok(_)) => unreachable!(),
          });
          entry.refresh = Instant::now() + self.retry;
        }
      }
    }
    if queried {
      entry.updated = Instant::now();
    }
    let addresses = entry
      .addresses
      .iter()
      .map(|ip| SocketAddr::new(*ip, port))
      .collect::<Vec<_>>();
    if queried && let Some(ctx) = ctx {
      let observation = ConnectionObservation::new();
      observation.dns(
        &host,
        started.elapsed(),
        self.timeout,
        &addresses,
      );
      observation.record(ctx);
    }
    if addresses.is_empty() {
      return Err(UpstreamError::DnsError(
        entry
          .error
          .clone()
          .unwrap_or_else(|| format!("no addresses for {host}")),
      ));
    }
    Ok(addresses)
  }
}
