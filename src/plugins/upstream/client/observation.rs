//! module: observation
//! responsibility: attribute physical transport setup to requests
//! without owning request state public operations:
//! ConnectionObservation::{new,dns,tcp,tls,record,error,
//! record_error,same_connection} data entities: ConnectionObservation,
//! Snapshot, DnsObservation, ObservedError tests: observation_tests.rs
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::context::RequestContext;
use crate::context::fields::{connection, dns};

#[derive(Clone, Debug)]
pub(super) struct ConnectionObservation(Arc<Snapshot>);
#[derive(Debug, Default)]
struct Snapshot {
  used: AtomicBool,
  dns: OnceLock<DnsObservation>,
  endpoints: OnceLock<(Option<SocketAddr>, Option<SocketAddr>)>,
  tcp: OnceLock<Duration>,
  tls: OnceLock<Duration>,
}
#[derive(Debug)]
struct DnsObservation {
  host: Arc<str>,
  elapsed: Duration,
  deadline: Duration,
  addresses: Arc<[IpAddr]>,
}
#[derive(Debug)]
struct ObservedError {
  observation: ConnectionObservation,
  source: std::io::Error,
}
impl std::fmt::Display for ObservedError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.source.fmt(f)
  }
}
impl Error for ObservedError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    Some(&self.source)
  }
}

impl ConnectionObservation {
  pub(super) fn same_connection(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }

  pub(super) fn endpoint(
    &self,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
  ) {
    self
      .0
      .endpoints
      .set((peer, local))
      .expect("connection endpoints set once");
  }

  pub(super) fn peer(&self) -> Option<SocketAddr> {
    self.0.endpoints.get().and_then(|(peer, _)| *peer)
  }

  pub(super) fn new() -> Self {
    Self(Arc::new(Snapshot::default()))
  }

  pub(super) fn dns(
    &self,
    host: &str,
    elapsed: Duration,
    deadline: Duration,
    addresses: &[SocketAddr],
  ) {
    if host.parse::<IpAddr>().is_ok()
      || host.parse::<SocketAddr>().is_ok()
    {
      return;
    }
    self
      .0
      .dns
      .set(DnsObservation {
        host: Arc::from(host),
        elapsed,
        deadline,
        addresses: addresses.iter().map(SocketAddr::ip).collect(),
      })
      .expect("DNS setup recorded once");
  }

  pub(super) fn tcp(
    &self,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    elapsed: Duration,
  ) {
    self.endpoint(peer, local);
    self
      .0
      .tcp
      .set(elapsed.saturating_sub(
        self.0.dns.get().map(|dns| dns.elapsed).unwrap_or_default(),
      ))
      .expect("TCP setup recorded once");
  }

  pub(super) fn tls(&self, elapsed: Duration) {
    self.0.tls.set(elapsed).expect("TLS setup recorded once");
  }

  pub(super) fn record(&self, ctx: &RequestContext) {
    let data = &self.0;
    let used = data.used.swap(true, Ordering::Relaxed);
    ctx.set(connection::REUSED, used);
    if let Some((peer, local)) = data.endpoints.get() {
      if let Some(peer) = peer {
        ctx.set(connection::PEER, *peer);
      }
      if let Some(local) = local {
        ctx.set(connection::LOCAL, *local);
      }
    }
    if !used {
      if let Some(dns) = data.dns.get() {
        ctx.set(dns::HOST, dns.host.clone());
        ctx.set(dns::TIME, dns.elapsed);
        ctx.set(dns::DEADLINE, dns.deadline);
        ctx.set(dns::ADDRESSES, dns.addresses.clone());
      }
      if let Some(elapsed) = data.tcp.get() {
        ctx.set(connection::CONNECT_TIME, *elapsed);
      }
      if let Some(elapsed) = data.tls.get() {
        ctx.set(connection::TLS_TIME, *elapsed);
      }
    }
  }

  pub(super) fn error(&self, source: std::io::Error) -> std::io::Error {
    std::io::Error::new(
      source.kind(),
      ObservedError { observation: self.clone(), source },
    )
  }

  pub(super) fn record_error(
    error: &(dyn Error + 'static),
    ctx: &RequestContext,
  ) {
    let mut current = Some(error);
    while let Some(error) = current {
      if let Some(error) = error.downcast_ref::<std::io::Error>()
        && let Some(inner) = error.get_ref()
        && let Some(observed) = inner.downcast_ref::<ObservedError>()
      {
        observed.observation.record(ctx);
        return;
      }
      if let Some(error) = error.downcast_ref::<ObservedError>() {
        error.observation.record(ctx);
        return;
      }
      current = error.source();
    }
  }
}
