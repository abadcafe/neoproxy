//! Public HTTP/1 framing contracts, without consuming a pending body.

use bytes::Bytes;
use http_body::Frame;
use http_body_util::{Empty, Full, StreamBody};

use super::http1_framing::prepare_request;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};

#[test]
fn test_prepare_request_does_not_poll_or_buffer_pending_request_content()
 {
  let body = StreamBody::new(futures::stream::pending::<
    Result<Frame<Bytes>, std::io::Error>,
  >());
  let mut request = http::Request::builder()
    .method("GET")
    .version(http::Version::HTTP_3)
    .body(RequestBody::new(BytesBufBodyWrapper::new(body)))
    .unwrap();
  prepare_request(&mut request);
  assert_eq!(request.version(), http::Version::HTTP_11);
  assert_eq!(request.headers()["transfer-encoding"], "chunked");
  assert!(!request.headers().contains_key("content-length"));
}

#[test]
fn test_prepare_request_preserves_explicit_content_length() {
  let mut request = http::Request::builder()
    .method("GET")
    .header("content-length", "7")
    .body(RequestBody::new(BytesBufBodyWrapper::new(Full::new(
      Bytes::from_static(b"payload"),
    ))))
    .unwrap();
  prepare_request(&mut request);
  assert_eq!(request.headers()["content-length"], "7");
  assert!(!request.headers().contains_key("transfer-encoding"));
}

#[test]
fn test_prepare_request_keeps_empty_request_without_transfer_coding() {
  let mut request = http::Request::new(RequestBody::new(
    BytesBufBodyWrapper::new(Empty::<Bytes>::new()),
  ));
  prepare_request(&mut request);
  assert!(!request.headers().contains_key("transfer-encoding"));
}
