use http_body_util::BodyExt;

use super::service_test_support::{
  body_string, make_req, write_js_file,
};
use crate::http_message::build_empty_response;

#[tokio::test]
async fn test_make_req_builds_request_with_headers_and_body() {
  let req = make_req(
    Some("sandbox-a"),
    http::Method::POST,
    "/run",
    b"payload",
    &[("x-test", "1")],
  );

  assert_eq!(req.method(), http::Method::POST);
  assert_eq!(req.uri(), "/run");
  assert_eq!(req.headers()["sandbox-id"], "sandbox-a");
  assert_eq!(req.headers()["x-test"], "1");

  let bytes = req.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(bytes, "payload");
}

#[tokio::test]
async fn test_body_string_reads_response_body() {
  let response = build_empty_response(http::StatusCode::CREATED);

  assert_eq!(body_string(response).await, "");
}

#[test]
fn test_write_js_file_writes_named_script() {
  let dir = tempfile::tempdir().unwrap();

  write_js_file(dir.path(), "handler", "export default {};");

  assert_eq!(
    std::fs::read_to_string(dir.path().join("handler.js")).unwrap(),
    "export default {};"
  );
}
