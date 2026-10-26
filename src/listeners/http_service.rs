//! Shared HTTP service adaptor for HTTP/HTTPS listeners.
//!
//! Provides a unified `hyper::Service` implementation that handles
//! request routing, authenticated-connection requirements, and context
//! injection for both HTTP and HTTPS listeners.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::Result;
use hyper::{body as hyper_body, service as hyper_svc};
use tower::util as tower_util;

use crate::context::build_request_context;
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response,
};
use crate::listeners::error_response::build_403_forbidden;
use crate::listeners::header_validation::validate_and_route;
use crate::server::ServerRouter;

/// Connection authentication state supplied by the listener.
pub(crate) enum ClientCertPolicy {
  /// HTTP listener — TLS not involved, no client cert to check.
  NotApplicable,
  /// HTTPS listener — any presented certificate has already passed
  /// TLS authentication against this listener's combined CA roots.
  Presented(bool),
}

impl ClientCertPolicy {
  fn is_absent(&self) -> bool {
    matches!(self, Self::Presented(false))
  }
}

/// Unified HTTP/HTTPS service adaptor with routing support.
///
/// Handles request validation, routing, connection authentication
/// requirements, and service invocation for HTTP and HTTPS listeners.
pub(crate) struct HttpServiceAdaptor {
  /// Server router for hostname-based routing
  server_router: ServerRouter,
  /// Client (peer) address from accept
  client_addr: Option<SocketAddr>,
  /// Local (server) address from accept
  local_addr: Option<SocketAddr>,
  /// Client authentication state from the TLS handshake
  client_cert_policy: ClientCertPolicy,
}

impl HttpServiceAdaptor {
  /// Create a new adaptor for HTTP (no TLS).
  pub(crate) fn new_http(
    server_router: ServerRouter,
    client_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
  ) -> Self {
    Self {
      server_router,
      client_addr,
      local_addr,
      client_cert_policy: ClientCertPolicy::NotApplicable,
    }
  }

  /// Create a new adaptor for HTTPS (with TLS).
  pub(crate) fn new_https(
    server_router: ServerRouter,
    client_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    client_cert_presented: bool,
  ) -> Self {
    Self {
      server_router,
      client_addr,
      local_addr,
      client_cert_policy: ClientCertPolicy::Presented(
        client_cert_presented,
      ),
    }
  }
}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HttpServiceAdaptor
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn call(
    &self,
    req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    let (parts, body) = req.into_parts();
    let mut req = Request::from_parts(
      parts,
      RequestBody::new(BytesBufBodyWrapper::new(body)),
    );

    // Validate headers and route to correct server
    let routing_entry =
      match validate_and_route(&req, &self.server_router) {
        Ok(entry) => entry,
        Err(resp) => return Box::pin(async { Ok(*resp) }),
      };

    // TLS already authenticated any presented certificate against
    // this listener's combined CA roots. Routing only determines
    // whether an anonymous connection may access this server; do not
    // revalidate the chain against the request server's CA subset.
    // SNI selects the TLS certificate, while authority/Host routes the
    // request. Proxy destinations need not equal the proxy's SNI.
    if routing_entry.requires_client_cert()
      && self.client_cert_policy.is_absent()
    {
      return Box::pin(async {
        Ok(build_403_forbidden(
          "Forbidden: client certificate required",
        ))
      });
    }

    // Build RequestContext with connection-level keys and
    // insert into request extensions. Auth and access logging are
    // now handled by the plugin layer in the service pipeline.
    if let (Some(peer_addr), Some(local_addr)) =
      (self.client_addr, self.local_addr)
    {
      let ctx = build_request_context(
        &peer_addr,
        &local_addr,
        &routing_entry.service_name,
      );

      req.extensions_mut().insert(ctx);
    }

    // Call service (auth/access_log handled by layers)
    let s = routing_entry.service.clone();
    Box::pin(async move { tower_util::Oneshot::new(s, req).await })
  }
}
