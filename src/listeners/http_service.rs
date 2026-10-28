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
use http_body_util::BodyExt;
use hyper::{body as hyper_body, service as hyper_svc};
use tower::util as tower_util;

use crate::context::{RequestContext, build_request_context};
use crate::http_message::{Request, RequestBody, Response};
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
  policy: super::http_policy::HttpPolicy,
  write_control: Option<super::write_deadline::Control>,
  reads: Option<crate::io_progress::Progress>,
  first_header:
    std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
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
      policy: Default::default(),
      write_control: None,
      reads: None,
      first_header: std::sync::Mutex::new(None),
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
      policy: Default::default(),
      write_control: None,
      reads: None,
      first_header: std::sync::Mutex::new(None),
      server_router,
      client_addr,
      local_addr,
      client_cert_policy: ClientCertPolicy::Presented(
        client_cert_presented,
      ),
    }
  }

  pub(super) fn with_first_header(
    mut self,
    sender: tokio::sync::oneshot::Sender<()>,
  ) -> Self {
    self.first_header = std::sync::Mutex::new(Some(sender));
    self
  }

  pub(super) fn with_write_control(
    mut self,
    control: super::write_deadline::Control,
  ) -> Self {
    self.write_control = Some(control);
    self
  }

  pub(super) fn with_reads(
    mut self,
    reads: crate::io_progress::Progress,
  ) -> Self {
    self.reads = Some(reads);
    self
  }

  pub(super) fn with_policy(
    mut self,
    policy: super::http_policy::HttpPolicy,
  ) -> Self {
    self.policy = policy;
    self
  }

  /// Route a transport-independent request and attach connection
  /// metadata.
  pub(crate) fn dispatch(
    &self,
    mut req: Request,
  ) -> Pin<Box<dyn Future<Output = Result<Response>>>> {
    if !self.policy.request_limits.limits().accepts(req.headers()) {
      return Box::pin(async {
        Ok(crate::http_message::build_error_response(
          http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
          "Too many request headers",
        ))
      });
    }
    let (parts, body) = req.into_parts();
    let (body, failure) = super::incoming_body::IncomingBody::wrap(
      body,
      self.policy,
      self.reads.clone(),
    );
    req = Request::from_parts(parts, body);
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
      let result = tokio::select! {
        biased;
        _ = failure.notified() => Ok(crate::http_message::build_empty_response(failure.status().expect("reported body failure"))),
        result = tower_util::Oneshot::new(s, req) => result,
      };
      // The service may observe the body error and finish in the same
      // poll.
      if let Some(status) = failure.status() {
        return Ok(identify_response(
          crate::http_message::build_empty_response(status),
          &ctx,
        ));
      }
      let response = match result {
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
    if let Some(sender) = self
      .first_header
      .lock()
      .expect("first header notification poisoned")
      .take()
    {
      let _ = sender.send(());
    }
    // Adapt only at the Hyper entry point, before shared dispatch.
    if let Some(upgrade) =
      req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>()
    {
      req.extensions_mut().insert(crate::stream::OnUpgrade::new(
        HttpUpgrade(upgrade, self.write_control.clone()),
      ));
    }
    let (parts, body) = req.into_parts();
    self.dispatch(Request::from_parts(
      parts,
      RequestBody::new(body.map_err(anyhow::Error::from)),
    ))
  }
}

/// Clone delegates directly to Hyper, which owns its shared receiver.
/// No additional Arc/Mutex is needed for this adapter.
#[derive(Clone)]
struct HttpUpgrade(
  hyper::upgrade::OnUpgrade,
  Option<super::write_deadline::Control>,
);

impl Future for HttpUpgrade {
  type Output = Result<Box<dyn crate::stream::Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Self::Output> {
    let this = self.get_mut();
    Pin::new(&mut this.0).poll(cx).map(|result| {
      // Retain Upgraded, including bytes pre-read by the HTTP parser.
      let stream = hyper_util::rt::TokioIo::new(result?);
      if let Some(control) = &this.1 {
        control.disable();
      }
      Ok(Box::new(stream) as Box<dyn crate::stream::Io>)
    })
  }
}
