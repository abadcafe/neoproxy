//! module: transport_factory
//! responsibility: construct a transport pool for a selected resolved
//! peer public operations: build, ClientEntry
//! data entities: ClientEntry
//! tests: client_tests.rs, test_upstream_nodes.py
use std::net::SocketAddr;
use std::sync::Arc;

use super::http::HttpProxyClient;
use super::http::connector::{ProxyConnector, TlsProxyConnector};
use super::http3::{Http3Client, SessionPool};
use super::protocol::{ClientProtocol, QuicConfig};
use crate::plugins::upstream::config::{self, Address, Protocol};
use crate::plugins::upstream::error::UpstreamError;
use crate::task_tracker::TaskTracker;

pub(super) struct ClientEntry {
  pub(super) tls: Arc<rustls::ClientConfig>,
  pub(super) client: Box<dyn ClientProtocol>,
  pub(super) timeouts: super::exchange_timeout::Timeouts,
  pub(super) protocol: config::protocol::ProtocolKind,
}
pub(super) fn build(
  config: &config::Upstream,
  address: &Address,
  endpoint: SocketAddr,
  tracker: &std::rc::Rc<TaskTracker>,
  connection_pools: &Arc<super::ConnectionPools>,
) -> Result<ClientEntry, UpstreamError> {
  let shared = connection_pools.get(&address.use_connection_pool);
  let tls = shared.tls.clone();
  if config.addresses.is_empty() {
    return Ok(ClientEntry {
      tls: tls.clone(),
      client: Box::new(
        super::direct::DirectClient::new(
          config,
          tls.clone(),
          endpoint,
          tracker.clone(),
          shared.clone(),
        )
        .map_err(|error| {
          UpstreamError::ProxyInternalError(error.to_string())
        })?,
      ),
      timeouts: super::exchange_timeout::Timeouts {
        read: address.upstream_read_timeout,
        send: address.upstream_send_timeout,
      },
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
      let pool = super::http_pool::ProxyPool::shared(
        connector,
        shared.http.clone(),
        super::http_cache::Key {
          endpoint,
          server_name: None,
          origin: None,
        },
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
        tls.clone(),
        hostname.clone(),
        *tls_handshake_timeout,
      );
      let pool = super::http_pool::ProxyPool::shared(
        connector,
        shared.https.clone(),
        super::http_cache::Key {
          endpoint,
          server_name: Some(hostname),
          origin: None,
        },
        tracker.clone(),
      );
      Box::new(HttpProxyClient::new(
        pool,
        address.tunnel_idle_timeout,
        address.user.clone(),
      ))
    }
    Protocol::Http3 { tls_handshake_timeout, quic } => {
      let session = SessionPool::shared(
        endpoint,
        Some(hostname),
        QuicConfig {
          datagram: quic.datagram.clone(),
          max_idle_timeout: quic.max_idle_timeout,
          keep_alive_interval: quic.keep_alive_interval,
          max_concurrent_bidi_streams: quic.max_concurrent_bidi_streams,
          initial_mtu: quic.initial_mtu,
          send_window: quic.send_window,
          receive_window: quic.receive_window,
          stream_receive_window: quic.stream_receive_window,
        },
        *tls_handshake_timeout,
        shared.h3.clone(),
        shared.h3_runtime.clone(),
      );
      Box::new(Http3Client {
        session,
        tunnel_idle_timeout: address.tunnel_idle_timeout,
        user: address.user.clone(),
      })
    }
  };
  Ok(ClientEntry {
    tls,
    client,
    timeouts: super::exchange_timeout::Timeouts {
      read: address.upstream_read_timeout,
      send: address.upstream_send_timeout,
    },
    protocol: address.address_protocol.kind(),
  })
}
