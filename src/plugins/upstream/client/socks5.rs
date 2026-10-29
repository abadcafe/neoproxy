//! module: socks5
//! responsibility: establish SOCKS5 upstream tunnels on selected TCP
//! peers public operations: Socks5Client::new, ClientProtocol
//! data entities: Socks5Client
//! tests: socks5_tests.rs, test_socks5_upstream.py

pub(super) mod handshake;
#[cfg(test)]
mod handshake_tests;

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tower::Service;

use super::http::ProxyIo;
use super::http::connector::ProxyConnector;
use super::observation::ConnectionObservation;
use super::protocol::{ClientProtocol, ConnectResult};
use crate::config::UserCredential;
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::upstream::error::{
  UpstreamError, classify_connect_error,
};
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

pub(super) struct Socks5Client {
  connector: ProxyConnector,
  tunnel_idle_timeout: Duration,
  user: Option<UserCredential>,
}

impl Socks5Client {
  pub(super) fn new(
    connector: ProxyConnector,
    tunnel_idle_timeout: Duration,
    user: Option<UserCredential>,
  ) -> Self {
    Self { connector, tunnel_idle_timeout, user }
  }
}

impl ClientProtocol for Socks5Client {
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    _target: &'a ForwardTarget,
    _req_headers: http::request::Parts,
    _req_body: RequestBody,
    _ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    Box::pin(async {
      Err(UpstreamError::DestinationUnavailable(
        "SOCKS5 requires CONNECT".into(),
      ))
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    request: &'a http::request::Parts,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    Box::pin(async move {
      let ctx = request.extensions.get::<RequestContext>();
      let io =
        self.connector.clone().call(target.uri()).await.map_err(
          |error| {
            if let Some(ctx) = ctx {
              ConnectionObservation::record_error(&error, ctx);
            }
            classify_connect_error(error.into())
          },
        )?;
      if let Some(ctx) = ctx {
        io.observation().record(ctx);
      }
      let peer = io.peer_addr().ok();
      let timeout = super::exchange_timeout::Control::default();
      timeout.start(
        request
          .extensions
          .get::<super::exchange_timeout::Timeouts>()
          .copied()
          .unwrap_or_default(),
      );
      timeout.response_started();
      let mut transport = TokioIo::new(
        super::exchange_timeout::TimedIo::new(io, timeout.clone()),
      );
      handshake::negotiate(&mut transport, target, self.user.as_ref())
        .await?;
      timeout.disable();
      Ok(ConnectResult {
        transport: Box::new(transport),
        upstream_addr: peer,
        upstream_response: None,
        tunnel_idle_timeout: self.tunnel_idle_timeout,
      })
    })
  }
}
