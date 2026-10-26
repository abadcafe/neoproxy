//! module: plugins::http_upstream::upstream::address_resolution
//! responsibility: bound system DNS work and its caller deadlines
//! public operations: resolve_addresses, TimeoutResolver, new
//! data entities: TimeoutResolver
//! tests: address_resolution_tests.rs

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hyper_util::client::legacy::connect::dns::Name;
use tower::Service;

use super::observation::ConnectionObservation;
use crate::plugins::http_upstream::error::DnsResolveError;

/// Preserve the DNS phase through connector APIs restricted to
/// io::Error.
pub(super) fn dns_io_error(error: std::io::Error) -> std::io::Error {
  std::io::Error::new(error.kind(), DnsResolveError(error))
}

// System getaddrinfo cannot be cancelled after entering libc. Keep its
// permit inside the blocking task even when the caller times out, so
// abandoned lookups cannot exhaust Tokio's blocking pool or queue.
static DNS_CAPACITY: tokio::sync::Semaphore =
  tokio::sync::Semaphore::const_new(64);

async fn lookup<T: std::net::ToSocketAddrs + Send + 'static>(
  address: T,
) -> std::io::Result<Vec<SocketAddr>> {
  let permit =
    DNS_CAPACITY.acquire().await.expect("DNS capacity is never closed");
  let lookup = tokio::task::spawn_blocking(move || {
    let _permit = permit;
    address.to_socket_addrs().map(|addresses| addresses.collect())
  });
  match lookup.await {
    Ok(result) => result,
    Err(error) if error.is_panic() => {
      std::panic::resume_unwind(error.into_panic())
    }
    Err(error) => {
      Err(std::io::Error::new(std::io::ErrorKind::Interrupted, error))
    }
  }
}

pub(crate) async fn resolve_addresses(
  address: &str,
) -> Result<Vec<SocketAddr>> {
  if let Ok(addr) = address.parse::<SocketAddr>() {
    return Ok(vec![addr]);
  }

  let addresses = lookup(address.to_owned()).await.map_err(|e| {
    anyhow::Error::from(DnsResolveError(e)).context(format!(
      "address '{address}' is neither IP:port nor resolvable hostname"
    ))
  })?;

  if addresses.is_empty() {
    return Err(anyhow!(
      "address '{address}' resolved to no addresses"
    ))
    .with_context(|| format!("address '{address}'"));
  }

  Ok(addresses)
}

#[derive(Clone, Debug)]
pub(crate) struct TimeoutResolver {
  timeout: Duration,
  observation: Option<ConnectionObservation>,
}

impl TimeoutResolver {
  pub(crate) fn new(timeout: Duration) -> Self {
    Self { timeout, observation: None }
  }

  pub(super) fn observe(
    mut self,
    observation: ConnectionObservation,
  ) -> Self {
    self.observation = Some(observation);
    self
  }
}

impl Service<Name> for TimeoutResolver {
  type Error = std::io::Error;
  type Future = Pin<
    Box<
      dyn std::future::Future<
          Output = Result<Self::Response, Self::Error>,
        > + Send,
    >,
  >;
  type Response = std::vec::IntoIter<SocketAddr>;

  fn poll_ready(
    &mut self,
    _cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, name: Name) -> Self::Future {
    let timeout = self.timeout;
    let host = name.to_string();
    let observation = self.observation.clone();
    Box::pin(async move {
      let started = std::time::Instant::now();
      let result =
        match tokio::time::timeout(timeout, lookup((host.clone(), 0)))
          .await
        {
          Ok(result) => result,
          Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS resolve timed out",
          )),
        };
      if let Some(observation) = &observation {
        observation.dns(
          &host,
          started.elapsed(),
          timeout,
          result.as_deref().unwrap_or_default(),
        );
      }
      result
        .map(|addresses| addresses.into_iter())
        .map_err(dns_io_error)
    })
  }
}
