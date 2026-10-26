//! Black-box tests for the http_message module.

use crate::http_message::{build_empty_response, build_error_response};

#[tokio::test]
async fn test_body_wrapper_filters_forbidden_trailers_and_preserves_data()
 {
  use bytes::Bytes;
  use http_body_util::{BodyExt, StreamBody};

  use crate::http_message::BytesBufBodyWrapper;

  let mut trailers = http::HeaderMap::new();
  for name in [
    "host",
    "content-length",
    "authorization",
    "proxy-authorization",
    "content-type",
  ] {
    trailers.insert(
      http::HeaderName::from_static(name),
      "private".parse().unwrap(),
    );
  }
  trailers.insert("x-checksum", "complete".parse().unwrap());
  let frames: Vec<Result<_, std::io::Error>> = vec![
    Ok(http_body::Frame::data(Bytes::from_static(b"body"))),
    Ok(http_body::Frame::trailers(trailers)),
  ];
  let body = BytesBufBodyWrapper::new(StreamBody::new(
    futures::stream::iter(frames),
  ));
  let collected = body.collect().await.unwrap();
  let trailers = collected.trailers().unwrap();
  assert_eq!(trailers.len(), 1);
  assert_eq!(trailers["x-checksum"], "complete");
  assert_eq!(collected.to_bytes(), "body");
}

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
