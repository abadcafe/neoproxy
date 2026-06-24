use super::request::{
  IncomingRequest, OutgoingResponse, SandboxConfig,
};

#[test]
fn test_sandbox_config_preserves_limits_and_source() {
  let config = SandboxConfig {
    sandbox_id: "sandbox-1".to_string(),
    heap_limit_bytes: 1024,
    cpu_limit_us: 5000,
    source_code: "export default {}".to_string(),
  };

  assert_eq!(config.sandbox_id, "sandbox-1");
  assert_eq!(config.heap_limit_bytes, 1024);
  assert_eq!(config.cpu_limit_us, 5000);
  assert_eq!(config.source_code, "export default {}");
}

#[test]
fn test_incoming_request_preserves_http_parts() {
  let request = IncomingRequest {
    method: "GET".to_string(),
    url: "/".to_string(),
    headers: vec![("accept".to_string(), "*/*".to_string())],
    body: vec![1, 2, 3],
  };

  assert_eq!(request.method, "GET");
  assert_eq!(request.url, "/");
  assert_eq!(request.headers.len(), 1);
  assert_eq!(request.body, vec![1, 2, 3]);
}

#[test]
fn test_outgoing_response_preserves_status_headers_and_body() {
  let response = OutgoingResponse {
    status: 204,
    headers: vec![("x-test".to_string(), "ok".to_string())],
    body: vec![],
  };

  assert_eq!(response.status, 204);
  assert_eq!(
    response.headers[0],
    ("x-test".to_string(), "ok".to_string())
  );
  assert!(response.body.is_empty());
}
