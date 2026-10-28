//! module: transport_factory
//! responsibility: construct a transport pool for a selected resolved
//! peer public operations: build, ClientEntry
//! data entities: ClientEntry
//! tests: client_tests.rs, test_upstream_nodes.py
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use super::http::HttpProxyClient;
use super::http::connector::{ProxyConnector, TlsProxyConnector};
use super::http3::{Http3Client, SessionPool};
use super::protocol::{ClientProtocol, QuicConfig};
use crate::plugins::upstream::config::{self, Address, Protocol};
use crate::plugins::upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

pub(super) struct ClientEntry {
  pub(super) client: Box<dyn ClientProtocol>,
  pub(super) request_timeout: Duration,
  pub(super) protocol: config::protocol::ProtocolKind,
}
pub(super) fn build(
  config: &config::Upstream,
  address: &Address,
  endpoint: SocketAddr,
  tls: &Option<Arc<rustls::ClientConfig>>,
  tracker: &Rc<StreamTracker>,
) -> Result<ClientEntry, UpstreamError> {
  let required_tls = || {
    tls.clone().ok_or_else(|| {
      UpstreamError::ProxyInternalError(
        "missing TLS configuration".into(),
      )
    })
  };
  if config.addresses.is_empty() {
    return Ok(ClientEntry {
      client: Box::new(
        super::direct::DirectClient::new(
          config,
          required_tls()?,
          endpoint,
        )
        .map_err(|error| {
          UpstreamError::ProxyInternalError(error.to_string())
        })?,
      ),
      request_timeout: address.upstream_request_timeout,
      protocol: address.address_protocol.kind(),
    });
  }
  let hostname = address.hostname.clone().unwrap_or_else(|| {
    address
      .address
      .parse::<http::uri::Authority>()
      .expect("validated upstream authority")
      .host()
      .trim_start_matches('[')
      .trim_end_matches(']')
      .to_owned()
  });
  let options = crate::tcp_options::TcpOptions {
    time: address.tcp_keep_alive_time,
    interval: address.tcp_keep_alive_interval,
    retries: address.tcp_keep_alive_retries,
  };
  let client: Box<dyn ClientProtocol> = match &address.address_protocol
  {
    Protocol::Socks5 { connect_timeout } => {
      let connector = ProxyConnector::new(endpoint, *connect_timeout)
        .with_tcp_options(options);
      Box::new(super::socks5::Socks5Client::new(
        connector,
        address.tunnel_idle_timeout,
        address.user.clone(),
      ))
    }
    Protocol::Http { connect_timeout } => {
      let connector = ProxyConnector::new(endpoint, *connect_timeout)
        .with_tcp_options(options);
      let pool = super::http_pool::ProxyPool::new(
        connector,
        config.pool_config.max_idle_per_host,
        config.pool_config.idle_timeout,
        tracker.clone(),
      );
      Box::new(HttpProxyClient::new(
        pool,
        address.tunnel_idle_timeout,
        address.user.clone(),
      ))
    }
    Protocol::Https { connect_timeout, tls_handshake_timeout } => {
      let inner = ProxyConnector::new(endpoint, *connect_timeout)
        .with_tcp_options(options);
      let connector = TlsProxyConnector::new(
        inner,
        required_tls()?,
        hostname,
        *tls_handshake_timeout,
      );
      let pool = super::http_pool::ProxyPool::new(
        connector,
        config.pool_config.max_idle_per_host,
        config.pool_config.idle_timeout,
        tracker.clone(),
      );
      Box::new(HttpProxyClient::new(
        pool,
        address.tunnel_idle_timeout,
        address.user.clone(),
      ))
    }
    Protocol::Http3 { tls_handshake_timeout, quic } => {
      let session = SessionPool::new(
        endpoint,
        Some(hostname),
        QuicConfig {
          max_idle_timeout: quic.max_idle_timeout,
          keep_alive_interval: quic.keep_alive_interval,
          max_concurrent_bidi_streams: quic.max_concurrent_bidi_streams,
          initial_mtu: quic.initial_mtu,
          send_window: quic.send_window,
          receive_window: quic.receive_window,
          stream_receive_window: quic.stream_receive_window,
        },
        *tls_handshake_timeout,
        config.pool_config.clone(),
      );
      Box::new(Http3Client {
        session,
        tunnel_idle_timeout: address.tunnel_idle_timeout,
        user: address.user.clone(),
      })
    }
  };
  Ok(ClientEntry {
    client,
    request_timeout: address.upstream_request_timeout,
    protocol: address.address_protocol.kind(),
  })
}
