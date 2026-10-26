//! module: direct
//! responsibilities: forward HTTP requests or open tunnels directly to
//! their target public operations: DirectClient::new, ClientProtocol
//! data entities: DirectClient
//! tests: direct_tests.rs
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

use super::address_resolution::{TimeoutResolver, resolve_addresses};
use super::forward::chain_forward_http;
use super::protocol::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::http_upstream::config;
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_connect_error,
};
use crate::plugins::http_upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

pub(super) struct DirectClient {
  client: Client<HttpConnector<TimeoutResolver>, RequestBody>,
  connect_timeout: Duration,
  tunnel_idle_timeout: Duration,
  dns_resolve_timeout: Duration,
}
impl DirectClient {
  pub(super) fn new(config: &config::Upstream) -> Self {
    let mut connector = HttpConnector::new_with_resolver(
      TimeoutResolver::new(config.dns_resolve_timeout),
    );
    connector.set_connect_timeout(Some(config.connect_timeout));
    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
      .pool_timer(hyper_util::rt::TokioTimer::new())
      .pool_max_idle_per_host(config.pool_config.max_idle_per_host)
      .pool_idle_timeout(config.pool_config.idle_timeout)
      .build(connector);
    Self {
      client,
      connect_timeout: config.connect_timeout,
      tunnel_idle_timeout: config.tunnel_idle_timeout,
      dns_resolve_timeout: config.dns_resolve_timeout,
    }
  }
}
impl ClientProtocol for DirectClient {
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let client = self.client.clone();

    Box::pin(async move {
      Ok(
        chain_forward_http(
          client,
          None,
          target,
          req_headers,
          req_body,
          ctx,
        )
        .await,
      )
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    _tls: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let connect_timeout = self.connect_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    Box::pin(async move {
      let dns_timeout = self.dns_resolve_timeout;
      let resolved = tokio::time::timeout(
        dns_timeout,
        resolve_addresses(target.authority()),
      )
      .await
      .map_err(|_| {
        UpstreamError::DnsError(format!(
          "DNS resolve for '{target}' timed out"
        ))
      })?
      .map_err(classify_connect_error)?;

      // Direct mode: raw TCP connect to target
      let stream =
        super::tcp_connect::connect(resolved, connect_timeout)
          .await
          .map_err(|e| classify_connect_error(e.into()))?;

      let upstream_addr = stream.peer_addr().ok();

      Ok(ConnectResult {
        transport: Box::new(stream),
        upstream_addr,
        upstream_proxy_status: None,
        tunnel_idle_timeout,
      })
    })
  }
}
