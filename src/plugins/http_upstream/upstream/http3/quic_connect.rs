//! module: quic_connect
//! responsibility: establish QUIC against reachable resolved addresses
//! public operations: connect
//! data entities: none
//! tests: quic_connect_tests.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::address_race::{self, RaceError};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_quic_error,
};

pub(super) async fn connect(
  addresses: Vec<SocketAddr>,
  hostname: &str,
  config: quinn::ClientConfig,
  timeout: Duration,
) -> Result<quinn::Connection, UpstreamError> {
  address_race::connect(addresses, timeout, |address| {
    let hostname = hostname.to_owned();
    let config = config.clone();
    async move {
      let bind = SocketAddr::new(
        if address.is_ipv4() {
          IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
          IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
      );
      let mut endpoint =
        quinn::Endpoint::client(bind).map_err(|error| {
          UpstreamError::ProxyInternalError(format!(
            "failed to create QUIC endpoint: {error}"
          ))
        })?;
      endpoint.set_default_client_config(config);
      endpoint
        .connect(address, &hostname)
        .map_err(|error| classify_quic_error(error.into()))?
        .await
        .map_err(|error| classify_quic_error(error.into()))
    }
  })
  .await
  .map_err(|error| match error {
    RaceError::NoAddresses => {
      UpstreamError::DnsError("no resolved QUIC addresses".into())
    }
    RaceError::InvalidDeadline => UpstreamError::ProxyInternalError(
      "QUIC handshake timeout exceeds clock range".into(),
    ),
    RaceError::Timeout => UpstreamError::ConnectionTimeout(
      "QUIC handshake deadline exceeded".into(),
    ),
    RaceError::Failed(error) => error,
  })
}
