use std::net::SocketAddr;

use anyhow::{Context, Result, anyhow};
use base64::Engine;

use crate::http_utils::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::error::DnsResolveError;

pub(crate) fn apply_proxy_auth(user: &Option<crate::config::UserCredential>, req: &mut http::Request<()>) {
  if let Some(user) = user {
    let credentials = base64::engine::general_purpose::STANDARD
      .encode(format!("{}:{}", user.username, user.password));
    req.headers_mut().insert(
      "Proxy-Authorization",
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap(),
    );
  }
}

pub(crate) fn resolve_address(s: &str) -> Result<SocketAddr> {
  s.parse()
    .or_else(|_| {
      std::net::ToSocketAddrs::to_socket_addrs(s)
        .map_err(|e| {
          anyhow::Error::from(DnsResolveError(e))
            .context(format!("address '{s}' is neither IP:port nor resolvable hostname"))
        })
        .and_then(|mut addrs| {
          addrs.next().ok_or_else(|| anyhow!("address '{s}' resolved to no addresses"))
        })
    })
    .with_context(|| format!("address '{s}'"))
}

pub(crate) fn build_connect_request(
  target: &str,
  user: &Option<crate::config::UserCredential>,
) -> http::Request<RequestBody> {
  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(target)
    .body(())
    .expect("building CONNECT request should not fail");
  apply_proxy_auth(user, &mut req);
  let empty = http_body_util::Empty::new();
  let wrapped = BytesBufBodyWrapper::new(empty);
  let body = RequestBody::new(wrapped);
  let (parts, _) = req.into_parts();
  http::Request::from_parts(parts, body)
}
