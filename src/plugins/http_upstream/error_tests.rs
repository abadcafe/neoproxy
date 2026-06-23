use super::error::*;
use crate::context::RequestContext;

#[test]
fn test_upstream_error_http_status() {
  assert_eq!(
    UpstreamError::DnsError("x".into()).http_status(),
    http::StatusCode::BAD_GATEWAY
  );
  assert_eq!(
    UpstreamError::ConnectionTimeout("x".into()).http_status(),
    http::StatusCode::GATEWAY_TIMEOUT
  );
  assert_eq!(
    UpstreamError::ProxyInternalError("x".into()).http_status(),
    http::StatusCode::SERVICE_UNAVAILABLE
  );
}

#[test]
fn test_upstream_error_proxy_status_error() {
  assert_eq!(
    UpstreamError::DnsError("x".into()).proxy_status_error(),
    "dns_error"
  );
  assert_eq!(
    UpstreamError::ConnectionTerminated("x".into())
      .proxy_status_error(),
    "connection_terminated"
  );
  assert_eq!(
    UpstreamError::TlsCertificateError("x".into()).proxy_status_error(),
    "tls_certificate_error"
  );
}

#[test]
fn test_to_response() {
  let ctx = RequestContext::new();
  ctx.insert("proxy_id", "test-proxy");
  let resp = UpstreamError::ConnectionRefused("conn refused".into())
    .to_response(&ctx);
  assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
  let ps = resp
    .headers()
    .get(http::header::HeaderName::from_static("proxy-status"))
    .unwrap()
    .to_str()
    .unwrap();
  assert!(ps.contains("connection_refused"));
  assert!(ps.contains("test-proxy"));
}

#[test]
fn test_classify_connect_error_connection_refused() {
  let io_err =
    std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
  let err: anyhow::Error = io_err.into();
  assert!(matches!(
    classify_connect_error(err),
    UpstreamError::ConnectionRefused(_)
  ));
}

#[test]
fn test_classify_connect_error_timed_out() {
  let io_err = std::io::Error::from(std::io::ErrorKind::TimedOut);
  let err: anyhow::Error = io_err.into();
  assert!(matches!(
    classify_connect_error(err),
    UpstreamError::ConnectionTimeout(_)
  ));
}

#[test]
fn test_classify_connect_error_connection_reset() {
  let io_err =
    std::io::Error::from(std::io::ErrorKind::ConnectionReset);
  let err: anyhow::Error = io_err.into();
  assert!(matches!(
    classify_connect_error(err),
    UpstreamError::ConnectionTerminated(_)
  ));
}

#[test]
fn test_classify_connect_error_dns_resolve() {
  let io_err = std::io::Error::new(
    std::io::ErrorKind::Other,
    "name lookup failed",
  );
  let err: anyhow::Error = DnsResolveError(io_err).into();
  assert!(matches!(
    classify_connect_error(err),
    UpstreamError::DnsError(_)
  ));
}

#[test]
fn test_classify_connect_error_host_unreachable() {
  let io_err =
    std::io::Error::from(std::io::ErrorKind::HostUnreachable);
  let err: anyhow::Error = io_err.into();
  assert!(matches!(
    classify_connect_error(err),
    UpstreamError::DestinationUnavailable(_)
  ));
}

#[test]
fn test_classify_quic_connection_error_timed_out() {
  let err: anyhow::Error = quinn::ConnectionError::TimedOut.into();
  assert!(matches!(
    classify_quic_error(err),
    UpstreamError::ConnectionTimeout(_)
  ));
}

#[test]
fn test_classify_quic_connection_error_reset_is_terminated() {
  let err: anyhow::Error = quinn::ConnectionError::Reset.into();
  assert!(matches!(
    classify_quic_error(err),
    UpstreamError::ConnectionTerminated(_)
  ));
}

#[test]
fn test_classify_quic_dns_resolve_error() {
  let io_err = std::io::Error::new(
    std::io::ErrorKind::Other,
    "name lookup failed",
  );
  let err: anyhow::Error = DnsResolveError(io_err).into();
  assert!(matches!(
    classify_quic_error(err),
    UpstreamError::DnsError(_)
  ));
}

#[test]
fn test_classify_tls_handshake_cert_error() {
  let tls_err = rustls::Error::NoCertificatesPresented;
  let err: anyhow::Error = tls_err.into();
  assert!(matches!(
    classify_tls_handshake_error(err),
    UpstreamError::TlsCertificateError(_)
  ));
}

#[test]
fn test_classify_tls_handshake_protocol_error() {
  let tls_err = rustls::Error::DecryptError;
  let err: anyhow::Error = tls_err.into();
  assert!(matches!(
    classify_tls_handshake_error(err),
    UpstreamError::TlsProtocolError(_)
  ));
}
