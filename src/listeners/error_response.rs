//! HTTP error response builders for listeners.
//!
//! Provides helpers for constructing common HTTP error responses
//! (403 Forbidden, 404 Not Found) used across HTTP-family listeners.

use crate::http_utils::{BytesBufBodyWrapper, Response, ResponseBody};

/// Build a 403 Forbidden response.
///
/// This response is sent when a server requires client certificate
/// authentication but the client did not present one.
pub(crate) fn build_403_forbidden(msg: &str) -> Response {
  let body =
    http_body_util::Full::new(bytes::Bytes::from(msg.to_string()));
  let bytes_buf = BytesBufBodyWrapper::new(body);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::FORBIDDEN;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}

/// Build a 404 Not Found response.
pub(crate) fn build_404_response() -> Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = BytesBufBodyWrapper::new(empty);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::NOT_FOUND;
  resp
}

