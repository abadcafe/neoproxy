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

use super::forward::forward_request;
use super::protocol::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::upstream::config;
use crate::plugins::upstream::error::{
  UpstreamError, classify_connect_error,
};
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

pub(super) struct DirectClient {
  connector: super::origin_connector::OriginConnector,
  tracker: Rc<StreamTracker>,
  shared: Arc<super::ConnectionPool>,
  connect_timeout: Duration,
  tunnel_idle_timeout: Duration,
  endpoint: std::net::SocketAddr,
  tcp_options: crate::tcp_options::TcpOptions,
}
impl DirectClient {
  pub(super) fn new(
    config: &config::Upstream,
    tls: Arc<rustls::ClientConfig>,
    endpoint: std::net::SocketAddr,
    tracker: Rc<StreamTracker>,
    shared: Arc<super::ConnectionPool>,
  ) -> anyhow::Result<Self> {
    Ok(Self {
      connector: super::origin_connector::OriginConnector::new(
        config, tls, endpoint,
      )?,
      tracker,
      shared,
      connect_timeout: config.connect_timeout,
      tunnel_idle_timeout: config.tunnel_idle_timeout,
      endpoint,
      tcp_options: crate::tcp_options::TcpOptions {
        time: config.tcp_keep_alive_time,
        interval: config.tcp_keep_alive_interval,
        retries: config.tcp_keep_alive_retries,
      },
    })
  }
}
impl ClientProtocol for DirectClient {
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    mut req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    Box::pin(async move {
      req_headers.headers.remove("alt-used");
      forward_request(
        super::http_pool::ProxyPool::shared(
          self.connector.clone(),
          if target.absolute_uri().scheme_str() == Some("https") {
            self.shared.https.clone()
          } else {
            self.shared.http.clone()
          },
          super::http_cache::Key {
            endpoint: self.endpoint,
            server_name: (target.absolute_uri().scheme_str()
              == Some("https"))
            .then(|| {
              target
                .absolute_uri()
                .host()
                .expect("validated host")
                .to_owned()
            }),
            origin: Some(
              target
                .absolute_uri()
                .authority()
                .expect("validated authority")
                .to_string(),
            ),
          },
          self.tracker.clone(),
        ),
        &None,
        target,
        req_headers,
        req_body,
        ctx,
      )
      .await
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    _target: &'a ConnectTarget,
    request: &'a ::http::request::Parts,
    _tls: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let connect_timeout = self.connect_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    Box::pin(async move {
      if request
        .extensions
        .get::<crate::connect_udp::request::Udp>()
        .is_some()
      {
        let transport =
          crate::connect_udp::direct::connect(self.endpoint)
            .await
            .map_err(|e| classify_connect_error(e.into()))?;
        return Ok(ConnectResult {
          transport,
          upstream_addr: Some(self.endpoint),
          upstream_response: None,
          tunnel_idle_timeout,
        });
      }
      let observation =
        super::observation::ConnectionObservation::new();
      let started = std::time::Instant::now();
      let result = super::tcp_connect::connect(
        vec![self.endpoint],
        connect_timeout,
      )
      .await
      .and_then(|stream| {
        self.tcp_options.apply(&stream)?;
        Ok(stream)
      })
      .map_err(|error| classify_connect_error(error.into()));
      observation.tcp(
        result.as_ref().ok().and_then(|stream| stream.peer_addr().ok()),
        result
          .as_ref()
          .ok()
          .and_then(|stream| stream.local_addr().ok()),
        started.elapsed(),
      );
      if let Some(ctx) = request.extensions.get::<RequestContext>() {
        observation.record(ctx);
      }
      let stream = result?;
      let upstream_addr = stream.peer_addr().ok();

      Ok(ConnectResult {
        transport: Box::new(stream),
        upstream_addr,
        upstream_response: None,
        tunnel_idle_timeout,
      })
    })
  }
}
