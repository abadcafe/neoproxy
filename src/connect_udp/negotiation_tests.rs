//! Wire negotiation contracts shared by HTTP-family UDP adapters.
use http::{HeaderMap, StatusCode};

use super::negotiation::{
  validate_http1_response, validate_http3_response,
};

#[test]
fn test_validate_http1_response_requires_upgrade_and_accepts_advisory_parameters()
 {
  let mut headers = HeaderMap::new();
  headers.insert("connection", "keep-alive, Upgrade".parse().unwrap());
  headers.insert("upgrade", "connect-udp".parse().unwrap());
  for field in [None, Some("?1"), Some("?1;future=token")] {
    headers.remove("capsule-protocol");
    if let Some(value) = field {
      headers.insert("capsule-protocol", value.parse().unwrap());
    }
    assert!(
      validate_http1_response(
        StatusCode::SWITCHING_PROTOCOLS,
        &headers
      )
      .is_ok()
    );
  }
  assert!(validate_http1_response(StatusCode::OK, &headers).is_err());
  let mut duplicate = headers.clone();
  duplicate.append("upgrade", "connect-udp".parse().unwrap());
  assert!(
    validate_http1_response(
      StatusCode::SWITCHING_PROTOCOLS,
      &duplicate
    )
    .is_err()
  );
  headers.remove("connection");
  assert!(
    validate_http1_response(StatusCode::SWITCHING_PROTOCOLS, &headers)
      .is_err()
  );
}

#[test]
fn test_validate_http3_response_rejects_content_statuses_and_content_headers()
 {
  let headers = HeaderMap::new();
  assert!(validate_http3_response(StatusCode::OK, &headers).is_ok());
  assert!(
    validate_http3_response(StatusCode::CREATED, &headers).is_ok()
  );
  for status in [
    StatusCode::NO_CONTENT,
    StatusCode::RESET_CONTENT,
    StatusCode::PARTIAL_CONTENT,
    StatusCode::BAD_GATEWAY,
  ] {
    assert!(validate_http3_response(status, &headers).is_err());
  }
  for name in ["content-length", "content-type", "transfer-encoding"] {
    let mut headers = HeaderMap::new();
    headers.insert(
      http::header::HeaderName::from_static(name),
      "0".parse().unwrap(),
    );
    assert!(
      validate_http3_response(StatusCode::OK, &headers).is_err(),
      "{name}"
    );
    headers.insert("connection", "Upgrade".parse().unwrap());
    headers.insert("upgrade", "connect-udp".parse().unwrap());
    assert!(
      validate_http1_response(
        StatusCode::SWITCHING_PROTOCOLS,
        &headers
      )
      .is_err(),
      "{name}"
    );
  }
}
