use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;

/// A wrapper for `Bytes` based `Body` types like `Full<Bytes>`,
/// `Empty<Bytes>`, etc in crate `http_body_util`. Through this wrapper,
/// different `Body` implements can be converted into `RequestBody` and
/// `ResponseBody` handily.
pub struct BytesBufBodyWrapper<B, E>(
  Pin<Box<dyn Body<Data = B, Error = E> + Send>>,
);

impl<B, E> BytesBufBodyWrapper<B, E> {
  pub fn new<T>(b: T) -> Self
  where
    T: Body<Data = B, Error = E> + Send + 'static,
    B: Buf,
    E: Error + Send + Sync,
  {
    Self(Box::pin(b))
  }
}

impl<B, E> Body for BytesBufBodyWrapper<B, E>
where
  B: Buf,
  E: Error + Send + Sync + 'static,
{
  type Data = B;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.0.as_mut().poll_frame(cx).map_err(|e| e.into())
  }

  fn is_end_stream(&self) -> bool {
    self.0.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.0.size_hint()
  }
}

pub type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type Request = http::Request<RequestBody>;
pub type Response = http::Response<ResponseBody>;

/// Build a Proxy-Status header value with just an identifier (success case).
#[cfg(test)]
pub fn build_proxy_status(identifier: &str) -> http::HeaderValue {
  http::HeaderValue::from_str(identifier)
    .unwrap_or_else(|_| http::HeaderValue::from_static("neoproxy"))
}

/// Build a Proxy-Status header value with an error parameter.
pub fn build_proxy_status_error(
  identifier: &str,
  error: &str,
) -> http::HeaderValue {
  let val = format!("{identifier}; error={error}");
  http::HeaderValue::from_str(&val)
    .unwrap_or_else(|_| http::HeaderValue::from_static("neoproxy; error=unknown"))
}

/// Build a Proxy-Status header value with received-status only (no error).
pub fn build_proxy_status_with_status(
  identifier: &str,
  status: u16,
) -> http::HeaderValue {
  let val = format!("{identifier}; received-status={status}");
  http::HeaderValue::from_str(&val)
    .unwrap_or_else(|_| http::HeaderValue::from_static("neoproxy"))
}

/// Append a new entry to an existing Proxy-Status Structured Fields List value.
///
/// Per RFC 9209 Section 2, intermediaries SHOULD preserve existing members of the
/// Proxy-Status field to allow debugging of the entire chain.  This function
/// combines the existing value (e.g. from the upstream proxy) with the current
/// proxy's entry by comma-separating them as required by the Structured Fields
/// List format.
pub fn append_proxy_status(
  existing: Option<&http::HeaderValue>,
  new_entry: &http::HeaderValue,
) -> http::HeaderValue {
  match existing {
    Some(existing_val) => {
      let combined = format!(
        "{}, {}",
        existing_val.to_str().unwrap_or(""),
        new_entry.to_str().unwrap_or("")
      );
      http::HeaderValue::from_str(&combined)
        .unwrap_or_else(|_| new_entry.clone())
    }
    None => new_entry.clone(),
  }
}

/// Build an empty response with the given status code.
pub fn build_empty_response(status: http::StatusCode) -> Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = BytesBufBodyWrapper::new(empty);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = status;
  resp
}

/// Build an error response with the given status code and message.
pub fn build_error_response(
  status: http::StatusCode,
  message: &str,
) -> Response {
  let full =
    http_body_util::Full::new(bytes::Bytes::from(message.to_string()));
  let bytes_buf = BytesBufBodyWrapper::new(full);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = status;
  resp.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain"),
  );
  resp
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_error_response_with_message() {
    let resp =
      build_error_response(http::StatusCode::BAD_REQUEST, "test error");
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }

  #[test]
  fn test_build_proxy_status() {
    let val = build_proxy_status("myproxy");
    assert_eq!(val.to_str().unwrap(), "myproxy");
  }

  #[test]
  fn test_build_proxy_status_error() {
    let val =
      build_proxy_status_error("myproxy", "connection_refused");
    assert_eq!(
      val.to_str().unwrap(),
      "myproxy; error=connection_refused"
    );
  }

  #[test]
  fn test_build_proxy_status_with_status() {
    let val = build_proxy_status_with_status("myproxy", 502);
    assert_eq!(
      val.to_str().unwrap(),
      "myproxy; received-status=502"
    );
  }

  #[test]
  fn test_build_proxy_status_fallback_on_invalid_identifier() {
    let val = build_proxy_status("my\x00proxy");
    assert_eq!(val.to_str().unwrap(), "neoproxy");
  }

  #[test]
  fn test_build_proxy_status_error_fallback() {
    let val =
      build_proxy_status_error("my\x00proxy", "connection_refused");
    assert_eq!(
      val.to_str().unwrap(),
      "neoproxy; error=unknown"
    );
  }

  #[test]
  fn test_append_proxy_status_no_existing() {
    let existing: Option<&http::HeaderValue> = None;
    let new_entry = build_proxy_status("myproxy");
    let val = append_proxy_status(existing, &new_entry);
    assert_eq!(val.to_str().unwrap(), "myproxy");
  }

  #[test]
  fn test_append_proxy_status_with_existing() {
    let existing = build_proxy_status("upproxy");
    let new_entry = build_proxy_status("myproxy");
    let val = append_proxy_status(Some(&existing), &new_entry);
    assert_eq!(
      val.to_str().unwrap(),
      "upproxy, myproxy"
    );
  }

  #[test]
  fn test_append_proxy_status_with_existing_with_params() {
    let existing =
      build_proxy_status_error("upproxy", "connection_refused");
    let new_entry =
      build_proxy_status_with_status("myproxy", 502);
    let val = append_proxy_status(Some(&existing), &new_entry);
    assert_eq!(
      val.to_str().unwrap(),
      "upproxy; error=connection_refused, myproxy; received-status=502"
    );
  }

  #[test]
  fn test_append_proxy_status_multi_member() {
    let existing = build_proxy_status_error("proxy-a", "dns_error");
    let mid = build_proxy_status("proxy-b");
    let val1 = append_proxy_status(Some(&existing), &mid);
    let new_entry = build_proxy_status_with_status("proxy-c", 502);
    let val2 = append_proxy_status(Some(&val1), &new_entry);
    assert_eq!(
      val2.to_str().unwrap(),
      "proxy-a; error=dns_error, proxy-b, proxy-c; received-status=502"
    );
  }
}
