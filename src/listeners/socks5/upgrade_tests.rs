use super::upgrade::http_status_to_socks5_error;

#[test]
fn test_http_status_to_socks5_error_proxy_auth_required() {
  assert!(matches!(
    http_status_to_socks5_error(
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    ),
    fast_socks5::ReplyError::ConnectionNotAllowed
  ));
}
