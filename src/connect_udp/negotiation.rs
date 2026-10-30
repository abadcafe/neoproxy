//! module: negotiation
//! responsibility: validate Capsule Protocol message negotiation
//! public operations: validate_headers, validate_http1_response,
//! validate_http3_response
//! data entities: none
//! tests: negotiation_tests.rs, connect_udp_tests.rs
use anyhow::{Result, ensure};
use http::{HeaderMap, StatusCode};

/// RFC 9297 §3.2 forbids HTTP content metadata on capsule streams.
/// Capsule-Protocol is advisory: connect-udp itself identifies the
/// protocol (§3.2, §3.4), so absent fields and unknown parameters do
/// not prevent negotiation. Our output always emits the canonical ?1.
pub(crate) fn validate_headers(headers: &HeaderMap) -> Result<()> {
  for name in ["content-length", "content-type", "transfer-encoding"] {
    ensure!(
      !headers.contains_key(name),
      "Capsule Protocol forbids {name}"
    );
  }
  Ok(())
}

pub(crate) fn validate_http1_response(
  status: StatusCode,
  headers: &HeaderMap,
) -> Result<()> {
  ensure!(
    status == StatusCode::SWITCHING_PROTOCOLS,
    "CONNECT-UDP requires status 101"
  );
  let mut upgrades = headers.get_all("upgrade").iter();
  ensure!(
    upgrades.next().is_some_and(|v| v
      .as_bytes()
      .eq_ignore_ascii_case(b"connect-udp"))
      && upgrades.next().is_none(),
    "CONNECT-UDP requires a single Upgrade: connect-udp"
  );
  ensure!(
    headers
      .get_all("connection")
      .iter()
      .filter_map(|v| v.to_str().ok())
      .flat_map(|v| v.split(','))
      .any(|v| v.trim().eq_ignore_ascii_case("upgrade")),
    "CONNECT-UDP requires Connection: Upgrade"
  );
  validate_headers(headers)
}

pub(crate) fn validate_http3_response(
  status: StatusCode,
  headers: &HeaderMap,
) -> Result<()> {
  ensure!(
    status.is_success()
      && !matches!(
        status,
        StatusCode::NO_CONTENT
          | StatusCode::RESET_CONTENT
          | StatusCode::PARTIAL_CONTENT
      ),
    "invalid Capsule Protocol response status"
  );
  validate_headers(headers)
}
