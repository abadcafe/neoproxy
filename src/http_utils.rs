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
pub fn build_error_response(status: http::StatusCode, message: &str) -> Response {
  let full = http_body_util::Full::new(bytes::Bytes::from(message.to_string()));
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
    let resp = build_error_response(http::StatusCode::BAD_REQUEST, "test error");
    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
  }
}
