//! Public contracts for request replay eligibility.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use super::retry_request::{Progress, RetryRequest};
use crate::http_message::{BytesBufBodyWrapper, RequestBody};

fn request(data: &'static [u8]) -> RetryRequest {
  RetryRequest::new(RequestBody::new(BytesBufBodyWrapper::new(
    Full::new(Bytes::from_static(data)),
  )))
}

#[test]
fn test_retry_before_send_allows_non_idempotent_requests() {
  assert!(request(b"upload").can_retry(
    &Progress::default(),
    &http::Method::POST,
    false
  ));
}

#[test]
fn test_retry_after_send_obeys_method_and_explicit_permission() {
  let progress = Progress::default();
  progress.mark();
  for method in [
    http::Method::GET,
    http::Method::HEAD,
    http::Method::PUT,
    http::Method::DELETE,
    http::Method::OPTIONS,
    http::Method::TRACE,
  ] {
    assert!(request(b"").can_retry(&progress, &method, false));
  }
  for method in [http::Method::POST, http::Method::PATCH] {
    assert!(!request(b"").can_retry(&progress, &method, false));
    assert!(request(b"").can_retry(&progress, &method, true));
  }
}

#[tokio::test]
async fn test_retry_never_replays_consumed_payload_even_when_enabled() {
  let request = request(b"upload");
  assert!(request.body().frame().await.is_some());
  assert!(!request.can_retry(
    &Progress::default(),
    &http::Method::PUT,
    true
  ));
}

#[tokio::test]
async fn test_retry_empty_body_remains_replayable_after_eof() {
  let request = request(b"");
  assert!(request.body().frame().await.is_none());
  let progress = Progress::default();
  progress.mark();
  assert!(request.can_retry(&progress, &http::Method::GET, false));
}
