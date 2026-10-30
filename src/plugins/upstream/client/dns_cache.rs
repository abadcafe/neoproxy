//! module: dns_cache
//! responsibility: cache TTL-bound DNS answers and retain stale answers
//! on failure public operations: DnsCache::{new,resolve}
//! data entities: DnsCache, Entry, Slot
//! tests: dns_cache_tests.rs; test_upstream_nodes.py
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
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

#[derive(Clone)]
struct Entry {
  addresses: Vec<IpAddr>,
  refresh: Instant,
  updated: Instant,
  error: Option<String>,
}
struct Slot {
  entry: RwLock<Arc<Entry>>,
  refresh: Mutex<()>,
}
impl Slot {
  fn snapshot(&self) -> Arc<Entry> {
    self.entry.read().expect("DNS snapshot poisoned").clone()
  }
}
pub(super) struct DnsCache {
  resolver: TokioResolver,
  timeout: Duration,
  retry: Duration,
  entries: std::sync::Mutex<RetainedCache<String, Arc<Slot>>>,
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
          Arc::new(Slot {
            entry: RwLock::new(Arc::new(Entry {
              addresses: Vec::new(),
              refresh: Instant::now(),
              updated: Instant::now(),
              error: None,
            })),
            refresh: Mutex::new(()),
          })
        },
        |slot| Arc::strong_count(slot) == 1,
      )
      .clone();
    let started = std::time::Instant::now();
    let waiting_since = Instant::now();
    let mut entry = slot.snapshot();
    let mut queried = false;
    if Instant::now() >= entry.refresh && entry.updated <= waiting_since
    {
      let _refresh = slot.refresh.lock().await;
      entry = slot.snapshot();
      queried = Instant::now() >= entry.refresh
        && entry.updated <= waiting_since;
      if queried {
        let mut next = (*entry).clone();
        let result = tokio::time::timeout(
          self.timeout,
          self.resolver.lookup_ip(format!("{host}.")),
        )
        .await;
        match result {
          Ok(Ok(lookup)) => {
            next.addresses = lookup.iter().collect();
            next.refresh = Instant::from_std(lookup.valid_until());
            next.error = None;
          }
          error => {
            next.error = Some(match error {
              Ok(Err(error)) => error.to_string(),
              Err(_) => "DNS resolve timed out".into(),
              Ok(Ok(_)) => unreachable!(),
            });
            next.refresh = Instant::now() + self.retry;
          }
        }
        next.updated = Instant::now();
        entry = Arc::new(next);
        *slot.entry.write().expect("DNS snapshot poisoned") =
          entry.clone();
      }
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
