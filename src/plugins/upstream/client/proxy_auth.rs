//! module: proxy_auth
//! responsibilities: manage authentication fields for an upstream hop
//! public operations: apply_proxy_auth, consume_proxy_auth_headers
//! data entities: none
//! tests: proxy_auth_tests.rs

use base64::Engine;

/// Consume the previous hop's proxy authentication fields before
/// choosing credentials for this upstream. No configured user means
/// no proxy credentials leave this hop.
pub(super) fn apply_proxy_auth<B>(
  user: &Option<crate::config::UserCredential>,
  req: &mut http::Request<B>,
) {
  consume_proxy_auth_headers(req.headers_mut());
  if let Some(user) = user {
    let credentials = base64::engine::general_purpose::STANDARD
      .encode(format!("{}:{}", user.username(), user.password()));
    req.headers_mut().insert(
      "Proxy-Authorization",
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap(),
    );
  }
}

/// Authentication fields from a completed upstream hop are consumed
/// here. Protocol encoders must preserve locally generated challenges
/// and must not apply this upstream forwarding policy.
pub(super) fn consume_proxy_auth_headers(
  headers: &mut http::HeaderMap,
) {
  headers.remove(http::header::PROXY_AUTHENTICATE);
  headers.remove(http::header::PROXY_AUTHORIZATION);
}
