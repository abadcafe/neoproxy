use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow};

use crate::plugins::http_upstream::error::DnsResolveError;

pub(crate) async fn resolve_address(
  address: &str,
) -> Result<SocketAddr> {
  if let Ok(addr) = address.parse::<SocketAddr>() {
    return Ok(addr);
  }

  tokio::net::lookup_host(address)
    .await
    .map_err(|e| {
      anyhow::Error::from(DnsResolveError(e)).context(format!(
        "address '{address}' is neither IP:port nor resolvable \
         hostname"
      ))
    })?
    .next()
    .ok_or_else(|| {
      anyhow!("address '{address}' resolved to no addresses")
    })
    .with_context(|| format!("address '{address}'"))
}
