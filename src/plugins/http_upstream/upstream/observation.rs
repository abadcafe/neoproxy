//! module: observation
//! responsibility: attribute physical transport setup to requests
//! without owning request state public operations:
//! ConnectionObservation::{new,dns,tcp,tls,protocol,record,error,
//! record_error,same_connection} data entities: ConnectionObservation,
//! Snapshot, DnsObservation, ObservedError tests: observation_tests.rs
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::context::RequestContext;
use crate::context::fields::{connection, dns};

#[derive(Clone, Debug)]
pub(super) struct ConnectionObservation(Arc<Mutex<Snapshot>>);
#[derive(Debug, Default)]
struct Snapshot {
  used: bool,
  dns: Option<DnsObservation>,
  peer: Option<SocketAddr>,
  local: Option<SocketAddr>,
  tcp: Option<Duration>,
  tls: Option<Duration>,
  alpn: Option<Arc<str>>,
  protocol: Option<Arc<str>>,
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
    let mut data = self.0.lock().expect("observation lock poisoned");
    data.peer = peer;
    data.local = local;
  }

  pub(super) fn peer(&self) -> Option<SocketAddr> {
    self.0.lock().expect("observation lock poisoned").peer
  }

  pub(super) fn new() -> Self {
    Self(Arc::new(Mutex::new(Snapshot::default())))
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
    self.0.lock().expect("observation lock poisoned").dns =
      Some(DnsObservation {
        host: Arc::from(host),
        elapsed,
        deadline,
        addresses: addresses.iter().map(SocketAddr::ip).collect(),
      });
  }

  pub(super) fn tcp(
    &self,
    peer: Option<SocketAddr>,
    local: Option<SocketAddr>,
    elapsed: Duration,
  ) {
    let mut data = self.0.lock().expect("observation lock poisoned");
    data.peer = peer;
    data.local = local;
    data.tcp = Some(elapsed.saturating_sub(
      data.dns.as_ref().map(|dns| dns.elapsed).unwrap_or_default(),
    ));
  }

  pub(super) fn tls(&self, elapsed: Duration, alpn: Option<&[u8]>) {
    let mut data = self.0.lock().expect("observation lock poisoned");
    data.tls = Some(elapsed);
    data.alpn = alpn
      .map(|value| Arc::from(String::from_utf8_lossy(value).as_ref()));
  }

  pub(super) fn protocol(&self, protocol: &str) {
    self.0.lock().expect("observation lock poisoned").protocol =
      Some(Arc::from(protocol));
  }

  pub(super) fn record(&self, ctx: &RequestContext) {
    let mut data = self.0.lock().expect("observation lock poisoned");
    ctx.set(connection::REUSED, data.used);
    if let Some(peer) = data.peer {
      ctx.set(connection::PEER, peer);
    }
    if let Some(local) = data.local {
      ctx.set(connection::LOCAL, local);
    }
    if let Some(alpn) = &data.alpn {
      ctx.set(connection::ALPN, alpn.clone());
    }
    if let Some(protocol) = &data.protocol {
      ctx.set(connection::PROTOCOL, protocol.clone());
    }
    if !data.used {
      if let Some(dns) = &data.dns {
        ctx.set(dns::HOST, dns.host.clone());
        ctx.set(dns::TIME, dns.elapsed);
        ctx.set(dns::DEADLINE, dns.deadline);
        ctx.set(dns::ADDRESSES, dns.addresses.clone());
      }
      if let Some(elapsed) = data.tcp {
        ctx.set(connection::CONNECT_TIME, elapsed);
      }
      if let Some(elapsed) = data.tls {
        ctx.set(connection::TLS_TIME, elapsed);
      }
    }
    data.used = true;
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
