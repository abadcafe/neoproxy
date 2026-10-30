//! module: http
//! responsibility: forward HTTP messages and negotiate tunnels over
//! proxy transports public operations: ProxyIo, HttpProxyClient::new,
//! ClientProtocol data entities: HttpProxyClient
//! tests: http_tests.rs; HTTP/HTTPS upstream process contracts

pub(super) mod connector;
#[cfg(test)]
mod connector_tests;
pub(super) mod transport;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use http::Uri;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;

use super::connect_request::build_connect_request;
use super::forward::forward_request;
use super::http_pool::ProxyPool;
use super::protocol::{ClientProtocol, ConnectResult};
pub(super) use super::transport_io::ProxyIo;
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody, Response};
use crate::plugins::upstream::error::{
  UpstreamError, classify_http_client_error,
};
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::task_tracker::TaskTracker;

pub(super) struct HttpProxyClient<C> {
  client: ProxyPool<C>,
  tunnel_idle_timeout: Duration,
  user: Option<crate::config::UserCredential>,
}

impl<C> HttpProxyClient<C> {
  pub(super) fn new(
    client: ProxyPool<C>,
    tunnel_idle_timeout: Duration,
    user: Option<crate::config::UserCredential>,
  ) -> Self {
    Self { client, tunnel_idle_timeout, user }
  }
}

impl<C> ClientProtocol for HttpProxyClient<C>
where
  C: tower::Service<Uri, Error = std::io::Error> + Clone,
  C::Response: ProxyIo,
{
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a std::sync::Arc<TaskTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    Box::pin(async move {
      forward_request(
        self.client.clone(),
        &self.user,
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
    target: &'a ConnectTarget,
    request: &'a ::http::request::Parts,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a std::sync::Arc<TaskTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    Box::pin(async move {
      let ctx = request.extensions.get::<RequestContext>();
      let io = self.client.connect(target.uri(), ctx).await?;
      if let Some(ctx) = ctx {
        io.observation().record(ctx);
      }
      let peer = io.peer_addr().ok();
      let mut request = request.clone();
      if let Some(udp) =
        request.extensions.get_mut::<crate::connect_udp::request::Udp>()
        && let Some(authority) = self.client.proxy_authority()
      {
        udp.authority = authority;
      }
      negotiate_tunnel(
        io,
        target,
        &request,
        &self.user,
        tracker,
        (peer, self.tunnel_idle_timeout),
        self.client.builder(),
      )
      .await
    })
  }
}

async fn negotiate_tunnel<I>(
  io: I,
  target: &ConnectTarget,
  request: &::http::request::Parts,
  user: &Option<crate::config::UserCredential>,
  tracker: &TaskTracker,
  (upstream_addr, tunnel_idle_timeout): (
    Option<std::net::SocketAddr>,
    Duration,
  ),
  builder: http1::Builder,
) -> Result<ConnectResult, UpstreamError>
where
  I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
  let timeout = super::exchange_timeout::Control::default();
  timeout.start(
    request
      .extensions
      .get::<super::exchange_timeout::Timeouts>()
      .copied()
      .unwrap_or_default(),
  );
  timeout.upload_complete();
  let io = super::exchange_timeout::TimedIo::new(io, timeout.clone());
  let (mut sr, conn) = builder.handshake(io).await.map_err(|e| {
    UpstreamError::ProxyInternalError(format!(
      "HTTP/1.1 handshake failed: {e}"
    ))
  })?;

  let mut req = build_connect_request(target, user, request);
  *req.version_mut() = http::Version::HTTP_11;
  let udp =
    request.extensions.get::<crate::connect_udp::request::Udp>();
  if let Some(udp) = udp {
    crate::connect_udp::request::apply(&mut req, udp, false);
  }
  let req = req.map(|()| {
    RequestBody::new(BytesBufBodyWrapper::new(
      http_body_util::Empty::new(),
    ))
  });
  let resp_fut = sr.send_request(req);

  // The CONNECT operation owns its HTTP driver. Cancelling this
  // operation drops both together, rather than leaving a detached task
  // until an I/O timeout. Keep polling the driver through upgrade.
  let mut driver = Box::pin(conn.with_upgrades());
  let shutdown = tracker.shutdown_handle();
  let mut driver_done = false;
  tokio::pin!(resp_fut);
  let mut resp = tokio::select! {
    biased;
    _ = shutdown.notified() => return Err(UpstreamError::ConnectionTerminated("upstream shutdown".into())),
    response = &mut resp_fut => response,
    result = &mut driver, if !driver_done => {
      driver_done = true;
      result.map_err(|error| classify_http_client_error(error.into()))?;
      resp_fut.await
    }
  }.map_err(|error| classify_http_client_error(error.into()))?;

  // RFC 9110 §9.3.6: every 2xx establishes a CONNECT tunnel.
  if if udp.is_some() {
    resp.status() != http::StatusCode::SWITCHING_PROTOCOLS
  } else {
    !resp.status().is_success()
  } {
    return Err(UpstreamError::UpstreamConnectError {
      status: resp.status(),
      upstream_proxy_status: crate::proxy_status::take_proxy_status(
        resp.headers_mut(),
      ),
    });
  }
  if udp.is_some() {
    crate::connect_udp::negotiation::validate_http1_response(
      resp.status(),
      resp.headers(),
    )
    .map_err(|error| {
      UpstreamError::InvalidResponse(error.to_string())
    })?;
  }

  // Hyper 1.6.0 incorrectly classifies 204 before checking CONNECT,
  // so it does not expose upgraded I/O for that status. Keep its real
  // failure visible; the dependency case is recorded in
  // tests/integration/test_connect_upstream_status.py.
  let upgrade = hyper::upgrade::on(&mut resp);
  tokio::pin!(upgrade);
  let upgraded = tokio::select! {
    biased;
    _ = shutdown.notified() => return Err(UpstreamError::ConnectionTerminated("upstream shutdown".into())),
    result = &mut upgrade => result,
    result = &mut driver, if !driver_done => {
      result.map_err(|error| classify_http_client_error(error.into()))?;
      upgrade.await
    }
  }.map_err(|e| {
    if e.is_user() {
      UpstreamError::InvalidResponse(e.to_string())
    } else {
      crate::plugins::upstream::error::classify_http_client_error(
        e.into(),
      )
    }
  })?;

  timeout.disable();
  Ok(ConnectResult {
    transport: Box::new(TokioIo::new(upgraded)),
    upstream_addr,
    upstream_response: Some(resp.into_parts().0),
    tunnel_idle_timeout,
  })
}
