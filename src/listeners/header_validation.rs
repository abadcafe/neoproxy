//! HTTP header validation for listener request routing.
//!
//! Provides authority-vs-host consistency checks and request routing
//! based on the Host header via ServerRouter.

use std::rc::Rc;

use crate::http_message::{Response, build_error_response};
use crate::server::{Server, ServerRouter};

/// Check if authority and Host header values differ.
///
/// Per RFC 9114 §4.3.1, if both `:authority` and Host are present,
/// they MUST contain the same value. Comparison is case-insensitive.
///
/// # Arguments
/// * `authority_str` - The full authority string (e.g.,
///   "example.com:443")
/// * `host_header` - The raw Host header value
///
/// # Returns
/// `true` if authority and Host differ (mismatch), `false` otherwise
pub(crate) fn authority_host_mismatch(
  authority_str: &str,
  host_header: &str,
) -> bool {
  if authority_str.is_empty() || host_header.is_empty() {
    return false;
  }
  authority_str.to_lowercase() != host_header.to_lowercase()
}

/// Validate request headers and route to the correct server.
///
/// Checks that a Host header is present, that it is consistent with
/// `:authority` (if present), and routes the request to a server via
/// the `ServerRouter`.
///
/// Returns `Ok(routing_entry)` on success, or `Err(error_response)`
/// if validation or routing fails.
pub(crate) fn validate_and_route<B>(
  req: &http::Request<B>,
  router: &ServerRouter,
) -> Result<Rc<Server>, Box<Response>> {
  // Host header is required
  let host_header = match req
    .headers()
    .get(http::header::HOST)
    .and_then(|h| h.to_str().ok())
    .map(|s| s.to_string())
  {
    Some(h) => h,
    None => {
      return Err(Box::new(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Bad Request: Host header is required",
      )));
    }
  };

  // If :authority exists, it must equal Host header
  if let Some(authority) = req.uri().authority()
    && authority_host_mismatch(authority.as_ref(), &host_header)
  {
    return Err(Box::new(build_error_response(
      http::StatusCode::BAD_REQUEST,
      "Bad Request: :authority and Host headers differ",
    )));
  }

  // Route via Host header
  let host = host_header.split(':').next().unwrap_or(&host_header);
  match router.route(Some(host)) {
    Some(entry) => Ok(entry),
    None => Err(Box::new(super::error_response::build_404_response())),
  }
}
