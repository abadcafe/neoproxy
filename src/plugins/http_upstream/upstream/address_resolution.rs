use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hyper_util::client::legacy::connect::dns::Name;
use tower::Service;

use crate::plugins::http_upstream::error::DnsResolveError;

pub(crate) async fn resolve_address(
  address: &str,
) -> Result<SocketAddr> {
  resolve_addresses(address)
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| {
      anyhow!("address '{address}' resolved to no addresses")
    })
    .with_context(|| format!("address '{address}'"))
}

pub(crate) async fn resolve_addresses(
  address: &str,
) -> Result<Vec<SocketAddr>> {
  if let Ok(addr) = address.parse::<SocketAddr>() {
    return Ok(vec![addr]);
  }

  let addresses: Vec<SocketAddr> = tokio::net::lookup_host(address)
    .await
    .map_err(|e| {
      anyhow::Error::from(DnsResolveError(e)).context(format!(
        "address '{address}' is neither IP:port nor resolvable \
         hostname"
      ))
    })?
    .collect();

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
}

impl TimeoutResolver {
  pub(crate) fn new(timeout: Duration) -> Self {
    Self { timeout }
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
    Box::pin(async move {
      let lookup = tokio::task::spawn_blocking(move || {
        std::net::ToSocketAddrs::to_socket_addrs(&(&*host, 0))
          .map(|iter| iter.collect::<Vec<_>>().into_iter())
      });
      tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| {
          std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS resolve timed out",
          )
        })?
        .map_err(|e| {
          if e.is_cancelled() {
            std::io::Error::new(std::io::ErrorKind::Interrupted, e)
          } else {
            std::io::Error::other(e)
          }
        })?
    })
  }
}
