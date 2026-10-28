//! Public contracts for listener request-body inactivity.
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};

use super::http_policy::HttpPolicy;
use super::incoming_body::IncomingBody;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};

#[tokio::test(start_paused = true)]
async fn test_incoming_body_pending_read_returns_408() {
  let body = StreamBody::new(futures_util::stream::pending::<
    Result<http_body::Frame<Bytes>, std::io::Error>,
  >());
  let (mut body, failure) = IncomingBody::wrap(
    RequestBody::new(BytesBufBodyWrapper::new(body)),
    HttpPolicy::default(),
    None,
  );
  assert!(body.frame().await.unwrap().is_err());
  assert_eq!(failure.status(), Some(http::StatusCode::REQUEST_TIMEOUT));
}

#[tokio::test(start_paused = true)]
async fn test_incoming_body_does_not_charge_time_before_consumption() {
  let body = http_body_util::Full::new(Bytes::from_static(b"stream"));
  let (mut body, failure) = IncomingBody::wrap(
    RequestBody::new(BytesBufBodyWrapper::new(body)),
    HttpPolicy::default(),
    None,
  );
  tokio::time::sleep(Duration::from_secs(120)).await;
  assert_eq!(
    body.frame().await.unwrap().unwrap().into_data().unwrap(),
    "stream"
  );
  assert_eq!(failure.status(), None);
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn test_incoming_body_rejects_repeated_trailers_over_count() {
  let mut trailers = http::HeaderMap::new();
  trailers.append("x-test", "a".parse().unwrap());
  trailers.append("x-test", "b".parse().unwrap());
  let body = StreamBody::new(futures_util::stream::iter([Ok::<
    _,
    std::io::Error,
  >(
    http_body::Frame::trailers(trailers),
  )]));
  let policy = serde_yaml::from_str("max_request_headers: 1").unwrap();
  let (mut body, failure) = IncomingBody::wrap(
    RequestBody::new(BytesBufBodyWrapper::new(body)),
    policy,
    None,
  );
  assert!(body.frame().await.unwrap().is_err());
  assert_eq!(
    failure.status(),
    Some(http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
  );
}
