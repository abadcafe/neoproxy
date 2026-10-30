//! module: layer
//! responsibility: authorize and attach sandbox-specific outbound
//! routes public operations: PolicyLayer::new, tower::Layer
//! data entities: PolicyLayer, Middleware
//! tests: e2b_tests.rs, test_e2b_policy.py
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::cache::Cache;
use crate::http_message::{Request, Response, build_error_response};
use crate::plugins::upstream::egress::Route;
use crate::service::Service;

pub(super) struct PolicyLayer {
  cache: Arc<Cache>,
}
impl PolicyLayer {
  pub(super) fn new(cache: Arc<Cache>) -> Self {
    Self { cache }
  }
}
impl tower::Layer<Service> for PolicyLayer {
  type Service = Service;

  fn layer(&self, inner: Service) -> Service {
    Service::new(Middleware { inner, cache: self.cache.clone() })
  }
}
#[derive(Clone)]
struct Middleware {
  inner: Service,
  cache: Arc<Cache>,
}
impl tower::Service<Request> for Middleware {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = anyhow::Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, mut req: Request) -> Self::Future {
    let cache = self.cache.clone();
    let replacement = self.inner.clone();
    let mut inner = std::mem::replace(&mut self.inner, replacement);
    Box::pin(async move {
      let mut ids = req.headers().get_all("x-sandbox-id").iter();
      let id = match (ids.next(), ids.next()) {
        (Some(value), None) => value
          .to_str()
          .ok()
          .filter(|id| {
            !id.is_empty()
              && id.len() <= 256
              && id.bytes().all(|b| b.is_ascii_graphic())
          })
          .map(str::to_owned),
        _ => None,
      };
      let Some(id) = id else {
        return Ok(build_error_response(
          http::StatusCode::FORBIDDEN,
          "Missing or invalid x-sandbox-id",
        ));
      };
      let snapshot = match cache.get(&id).await {
        Ok(snapshot) => snapshot,
        Err(_) => {
          return Ok(build_error_response(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "Sandbox policy capacity exhausted",
          ));
        }
      };
      let (parts, body) = req.into_parts();
      let udp = crate::connect_udp::request::recognize(&parts);
      if !matches!(udp, Ok(None)) {
        return Ok(build_error_response(
          http::StatusCode::FORBIDDEN,
          "E2B policies support TCP egress only",
        ));
      }
      req = Request::from_parts(parts, body);
      let is_connect = req.method() == http::Method::CONNECT;
      let authority = req
        .uri()
        .authority()
        .and_then(|a| crate::http_authority::normalize(a).ok());
      let Some(authority) = authority else {
        return Ok(build_error_response(
          http::StatusCode::BAD_REQUEST,
          "Invalid request target",
        ));
      };
      if !is_connect
        && !matches!(req.uri().scheme_str(), Some("http" | "https"))
      {
        return Ok(build_error_response(
          http::StatusCode::BAD_REQUEST,
          "Expected an HTTP(S) absolute-form target",
        ));
      }
      if is_connect && authority.port_u16().is_none() {
        return Ok(build_error_response(
          http::StatusCode::BAD_REQUEST,
          "CONNECT requires a port",
        ));
      }
      let host =
        authority.host().trim_start_matches('[').trim_end_matches(']');
      let domain_match = snapshot.policy.allows_domain(host);
      if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !snapshot.policy.allows_ip(ip)
      {
        return Ok(build_error_response(
          http::StatusCode::FORBIDDEN,
          "Destination denied by sandbox network policy",
        ));
      }
      req.extensions_mut().insert(Route::new(
        snapshot.policy.clone(),
        snapshot.policy.proxy(),
        domain_match,
      ));
      // Sandbox identity belongs to the central policy boundary, never
      // to the destination server or the user's outbound SOCKS5 proxy.
      req.headers_mut().remove("x-sandbox-id");
      inner.call(req).await
    })
  }
}
