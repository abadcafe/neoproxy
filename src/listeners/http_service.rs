//! module: listeners::http_service
//! responsibility: dispatch routed HTTP-family requests to the service
//! contract
//! public operations: HttpService, dispatch,
//! new_http, new_tls
//! data entities: ClientCertPolicy, HttpService, HttpUpgrade
//! tests: http_service_tests.rs

//! Shared HTTP service adaptor for HTTP-family listeners.
//!
//! Provides a unified `hyper::Service` implementation that handles
//! request routing, authenticated-connection requirements, and context
//! injection for HTTP, HTTPS and HTTP/3 listeners.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use anyhow::Result;
use hyper::{body as hyper_body, service as hyper_svc};
use tower::util as tower_util;

use crate::context::{RequestContext, build_request_context};
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response,
};
use crate::listeners::error_response::build_403_forbidden;
use crate::listeners::header_validation::validate_and_route;
use crate::server::ServerRouter;

/// Connection authentication state supplied by the listener.
enum ClientCertPolicy {
  /// HTTP listener — TLS not involved, no client cert to check.
  NotApplicable,
  /// TLS listener — any presented certificate has already passed
  /// TLS authentication against this listener's combined CA roots.
  Presented(bool),
}

impl ClientCertPolicy {
  fn is_absent(&self) -> bool {
    matches!(self, Self::Presented(false))
  }
}

/// Unified HTTP-family service adaptor with routing support.
///
/// Handles request validation, routing, connection authentication
/// requirements, and service invocation for HTTP, HTTPS and HTTP/3.
pub(crate) struct HttpService {
  /// Server router for hostname-based routing
  server_router: ServerRouter,
  /// Client (peer) address from accept
  client_addr: SocketAddr,
  /// Local (server) address from accept
  local_addr: SocketAddr,
  /// Client authentication state from the TLS handshake
  client_cert_policy: ClientCertPolicy,
}

impl HttpService {
  /// Create a new adaptor for HTTP (no TLS).
  pub(crate) fn new_http(
    server_router: ServerRouter,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
  ) -> Self {
    Self {
      server_router,
      client_addr,
      local_addr,
      client_cert_policy: ClientCertPolicy::NotApplicable,
    }
  }

  /// Create a service for a TLS-authenticated connection (HTTPS or H3).
  pub(crate) fn new_tls(
    server_router: ServerRouter,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
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

  /// Route a transport-independent request and attach connection
  /// metadata.
  pub(crate) fn dispatch(
    &self,
    mut req: Request,
  ) -> Pin<Box<dyn Future<Output = Result<Response>>>> {
    let id = match crate::request_id::RequestId::read_or_generate(
      req.headers(),
    ) {
      Ok(id) => id,
      Err(error) => {
        return Box::pin(async move {
          Err(anyhow::anyhow!("generating request ID: {error}"))
        });
      }
    };
    let ctx =
      build_request_context(&self.client_addr, &self.local_addr, "")
        .with_request_id(id);
    req.extensions_mut().insert(ctx.clone());
    // Validate headers and route to correct server
    let routing_entry =
      match validate_and_route(&req, &self.server_router) {
        Ok(entry) => entry,
        Err(resp) => {
          return Box::pin(async move {
            Ok(identify_response(*resp, &ctx))
          });
        }
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
      return Box::pin(async move {
        Ok(identify_response(
          build_403_forbidden("Forbidden: client certificate required"),
          &ctx,
        ))
      });
    }

    // Build RequestContext with connection-level keys and
    // insert into request extensions. Auth and access logging are
    // now handled by the plugin layer in the service pipeline.
    let ctx = ctx.with_service(&routing_entry.service_name);
    req.extensions_mut().insert(ctx.clone());
    crate::hop_headers::join_cookie_headers(req.headers_mut());

    // Call service (auth/access_log handled by layers)
    let s = routing_entry.service.clone();
    Box::pin(async move {
      let response = match tower_util::Oneshot::new(s, req).await {
        Ok(response) => response,
        Err(_) => crate::http_message::build_error_response(
          http::StatusCode::INTERNAL_SERVER_ERROR,
          "Internal Server Error",
        ),
      };
      Ok(identify_response(response, &ctx))
    })
  }
}

fn identify_response(
  mut response: Response,
  ctx: &RequestContext,
) -> Response {
  ctx
    .request_id()
    .expect("ingress established request identity")
    .apply(response.headers_mut());
  response.extensions_mut().insert(ctx.clone());
  response
}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HttpService
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn call(
    &self,
    mut req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    // Adapt only at the Hyper entry point, before shared dispatch.
    if let Some(upgrade) =
      req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>()
    {
      req
        .extensions_mut()
        .insert(crate::stream::OnUpgrade::new(HttpUpgrade(upgrade)));
    }
    let (parts, body) = req.into_parts();
    self.dispatch(Request::from_parts(
      parts,
      RequestBody::new(BytesBufBodyWrapper::new(body)),
    ))
  }
}

/// Clone delegates directly to Hyper, which owns its shared receiver.
/// No additional Arc/Mutex is needed for this adapter.
#[derive(Clone)]
struct HttpUpgrade(hyper::upgrade::OnUpgrade);

impl Future for HttpUpgrade {
  type Output = Result<Box<dyn crate::stream::Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Self::Output> {
    Pin::new(&mut self.get_mut().0).poll(cx).map(|result| {
      // Retain Upgraded, including bytes pre-read by the HTTP parser.
      let stream = hyper_util::rt::TokioIo::new(result?);
      Ok(Box::new(stream) as Box<dyn crate::stream::Io>)
    })
  }
}
