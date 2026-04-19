//! Unified authentication module for neoproxy.

mod config;
mod error;
mod password;
mod tls_cert;

#[allow(unused_imports)]
pub use config::UserCredential;
pub use config::{AuthConfig, AuthType};
pub use error::AuthError;
pub use password::verify_password;
pub use tls_cert::TlsClientCertVerifier;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use http::HeaderValue;

/// Parse Proxy-Authorization header (Basic Auth)
/// Returns (username, password) or error
pub fn parse_basic_auth(header: &HeaderValue) -> Result<(String, String), AuthError> {
  let header_str = header.to_str().map_err(|_| {
    AuthError::ConfigError("Invalid Proxy-Authorization header encoding".to_string())
  })?;

  if !header_str.starts_with("Basic ") {
    return Err(AuthError::ConfigError(
      "Not Basic authentication".to_string()
    ));
  }

  let encoded = &header_str[6..]; // Skip "Basic "
  let decoded = BASE64_STANDARD.decode(encoded).map_err(|_| {
    AuthError::ConfigError("Invalid Base64 encoding in credentials".to_string())
  })?;

  let decoded_str = String::from_utf8(decoded).map_err(|_| {
    AuthError::ConfigError("Invalid UTF-8 in credentials".to_string())
  })?;

  let mut parts = decoded_str.splitn(2, ':');
  let username = parts.next().unwrap_or("").to_string();
  let password = parts.next().unwrap_or("").to_string();

  if username.is_empty() {
    return Err(AuthError::ConfigError("Empty username in credentials".to_string()));
  }

  // Check for missing colon (no password separator found)
  if !decoded_str.contains(':') {
    return Err(AuthError::ConfigError("Missing colon separator in credentials".to_string()));
  }

  Ok((username, password))
}

#[cfg(test)]
mod parse_basic_auth_tests {
  use super::*;
  use http::HeaderValue;
  use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

  #[test]
  fn test_parse_basic_auth_valid() {
    let header = HeaderValue::from_str("Basic dXNlcjpwYXNzd29yZA==").unwrap();
    let result = parse_basic_auth(&header);
    assert!(result.is_ok());
    let (username, password) = result.unwrap();
    assert_eq!(username, "user");
    assert_eq!(password, "password");
  }

  #[test]
  fn test_parse_basic_auth_not_basic() {
    let header = HeaderValue::from_str("Bearer token123").unwrap();
    let result = parse_basic_auth(&header);
    assert!(result.is_err());
  }

  #[test]
  fn test_parse_basic_auth_missing_colon() {
    let encoded = BASE64_STANDARD.encode("userwithoutcolon");
    let header = HeaderValue::from_str(&format!("Basic {}", encoded)).unwrap();
    let result = parse_basic_auth(&header);
    assert!(result.is_err());
  }
}
