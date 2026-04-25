//! User/password authentication (HTTP application layer + SOCKS5).
//!
//! Handles HTTP Proxy-Authorization header verification and direct
//! username/password verification for SOCKS5.

use std::collections::HashMap;

use base64::{
  Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
};
use tracing::debug;

use crate::auth::listener_auth_config::ListenerAuthConfig;
use crate::auth::{AuthError, verify_password};

/// User/password authenticator.
///
/// Handles HTTP Proxy-Authorization header verification and direct
/// username/password verification (for SOCKS5).
/// When users are configured, authentication is REQUIRED.
#[derive(Debug, Clone)]
pub struct UserPasswordAuth {
  users: Option<HashMap<String, String>>,
}

impl UserPasswordAuth {
  /// Create a UserPasswordAuth with no verification (no password required).
  pub fn none() -> Self {
    Self { users: None }
  }

  /// Build from ListenerAuthConfig.
  ///
  /// If the config includes `users`, creates a verifier with the configured
  /// users. Otherwise returns `none()`. Pure memory operation, cannot fail.
  pub fn from_config(config: &ListenerAuthConfig) -> Self {
    match config.users_map() {
      Some(users) => Self { users: Some(users) },
      None => Self::none(),
    }
  }

  /// Verify the HTTP request's Proxy-Authorization header.
  ///
  /// Returns Ok(()) if authentication succeeds or no auth is configured.
  pub fn verify(
    &self,
    req: &http::Request<()>,
  ) -> Result<(), AuthError> {
    match &self.users {
      None => Ok(()),
      Some(users) => {
        let auth_header = req
          .headers()
          .get(http::header::PROXY_AUTHORIZATION)
          .ok_or(AuthError::InvalidCredentials)?;
        let (username, password) = Self::parse_basic_auth(auth_header)
          .inspect_err(|e| {
            debug!("Failed to parse Basic auth header: {}", e);
          })
          .map_err(|_| AuthError::InvalidCredentials)?;
        verify_password(users, &username, &password)
      }
    }
  }

  /// Verify credentials and return the username on success.
  ///
  /// Combines verification and username extraction in a single pass,
  /// avoiding redundant header parsing when both are needed.
  /// Returns Ok(None) if no auth is configured.
  /// Returns Ok(Some(username)) if auth succeeds.
  /// Returns Err if auth fails.
  pub fn verify_and_extract_username(
    &self,
    req: &http::Request<()>,
  ) -> Result<Option<String>, AuthError> {
    match &self.users {
      None => Ok(None),
      Some(users) => {
        let auth_header = req
          .headers()
          .get(http::header::PROXY_AUTHORIZATION)
          .ok_or(AuthError::InvalidCredentials)?;
        let (username, password) = Self::parse_basic_auth(auth_header)
          .inspect_err(|e| {
            debug!("Failed to parse Basic auth header: {}", e);
          })
          .map_err(|_| AuthError::InvalidCredentials)?;
        verify_password(users, &username, &password)?;
        Ok(Some(username))
      }
    }
  }

  /// Check if authentication is required (i.e., users are configured).
  ///
  /// This method is kept for potential use by other listeners (SOCKS5, HTTP/3)
  /// that may need to check auth requirements before processing.
  #[allow(dead_code)]
  pub fn is_auth_required(&self) -> bool {
    self.users.is_some()
  }

  /// Verify username/password directly (for SOCKS5).
  ///
  /// Returns Ok(()) if authentication succeeds or no auth is configured.
  pub fn verify_credentials(
    &self,
    username: &str,
    password: &str,
  ) -> Result<(), AuthError> {
    match &self.users {
      None => Ok(()),
      Some(users) => verify_password(users, username, password),
    }
  }

  /// Parse Proxy-Authorization header (Basic Auth).
  /// Returns (username, password) or error.
  fn parse_basic_auth(
    header: &http::HeaderValue,
  ) -> Result<(String, String), AuthError> {
    let header_str = header.to_str().map_err(|_| {
      AuthError::ConfigError(
        "Invalid Proxy-Authorization header encoding".to_string(),
      )
    })?;

    if !header_str.starts_with("Basic ") {
      return Err(AuthError::ConfigError(
        "Not Basic authentication".to_string(),
      ));
    }

    let encoded = &header_str[6..];
    let decoded = BASE64_STANDARD.decode(encoded).map_err(|_| {
      AuthError::ConfigError(
        "Invalid Base64 encoding in credentials".to_string(),
      )
    })?;

    let decoded_str = String::from_utf8(decoded).map_err(|_| {
      AuthError::ConfigError("Invalid UTF-8 in credentials".to_string())
    })?;

    if !decoded_str.contains(':') {
      return Err(AuthError::ConfigError(
        "Missing colon separator in credentials".to_string(),
      ));
    }

    let mut parts = decoded_str.splitn(2, ':');
    let username = parts.next().unwrap_or("").to_string();
    let password = parts.next().unwrap_or("").to_string();

    if username.is_empty() {
      return Err(AuthError::ConfigError(
        "Empty username in credentials".to_string(),
      ));
    }

    Ok((username, password))
  }

  /// Extract username from Proxy-Authorization header.
  ///
  /// Returns `Some(username)` if a valid Basic auth header is present,
  /// or `None` if the header is missing or malformed.
  /// This is used for access logging to record the authenticated user.
  ///
  /// This method is kept for potential use by other listeners (SOCKS5, HTTP/3)
  /// that may need to extract usernames for logging after separate auth verification.
  #[allow(dead_code)]
  pub fn extract_username(
    req: &http::Request<()>,
  ) -> Option<String> {
    req.headers()
      .get(http::header::PROXY_AUTHORIZATION)
      .and_then(|h| Self::parse_basic_auth(h).ok())
      .map(|(username, _)| username)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use base64::{
    Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
  };

  #[test]
  fn test_user_password_auth_none_passes_any_request() {
    let auth = UserPasswordAuth::none();
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("http://example.com:443")
      .body(())
      .unwrap();
    assert!(auth.verify(&req).is_ok());
  }

  #[test]
  fn test_user_password_auth_from_config_no_users() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: None,
        client_ca_path: Some("/path/to/ca.pem".to_string()),
      };
    let auth = UserPasswordAuth::from_config(&config);
    // No users → no password auth → verify always passes
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("http://example.com:443")
      .body(())
      .unwrap();
    assert!(auth.verify(&req).is_ok());
  }

  #[test]
  fn test_user_password_auth_from_config_with_users() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    // Valid credentials
    let credentials = BASE64_STANDARD.encode("admin:secret123");
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("http://example.com:443")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();
    assert!(auth.verify(&req).is_ok());
  }

  #[test]
  fn test_user_password_auth_verify_invalid_credentials() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    let credentials = BASE64_STANDARD.encode("admin:wrongpassword");
    let req = http::Request::builder()
      .method("CONNECT")
      .uri("http://example.com:443")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();
    assert!(auth.verify(&req).is_err());
  }

  #[test]
  fn test_user_password_auth_verify_missing_header() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    let req = http::Request::builder()
      .method("CONNECT")
      .uri("http://example.com:443")
      .body(())
      .unwrap();
    assert!(auth.verify(&req).is_err());
  }

  // ============== verify_credentials tests (for SOCKS5) ==============

  #[test]
  fn test_verify_credentials_valid() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "socks_user".to_string(),
            password: "socks_pass".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);
    assert!(
      auth.verify_credentials("socks_user", "socks_pass").is_ok()
    );
  }

  #[test]
  fn test_verify_credentials_invalid() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "socks_user".to_string(),
            password: "socks_pass".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);
    assert!(auth.verify_credentials("socks_user", "wrong").is_err());
  }

  #[test]
  fn test_verify_credentials_no_users_configured() {
    let auth = UserPasswordAuth::none();
    // No users configured → verify_credentials always passes
    assert!(auth.verify_credentials("anyone", "anything").is_ok());
  }

  #[test]
  fn test_is_auth_required_no_users() {
    let auth = UserPasswordAuth::none();
    assert!(!auth.is_auth_required());
  }

  #[test]
  fn test_is_auth_required_with_users() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);
    assert!(auth.is_auth_required());
  }

  // ============== extract_username tests ==============

  #[test]
  fn test_extract_username_valid_header() {
    let credentials = BASE64_STANDARD.encode("testuser:testpass");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();
    let username = UserPasswordAuth::extract_username(&req);
    assert_eq!(username, Some("testuser".to_string()));
  }

  #[test]
  fn test_extract_username_missing_header() {
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();
    let username = UserPasswordAuth::extract_username(&req);
    assert!(username.is_none());
  }

  #[test]
  fn test_extract_username_invalid_base64() {
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", "Basic !!!invalid!!!")
      .body(())
      .unwrap();
    let username = UserPasswordAuth::extract_username(&req);
    assert!(username.is_none());
  }

  #[test]
  fn test_extract_username_no_colon() {
    let credentials = BASE64_STANDARD.encode("usernocolon");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();
    let username = UserPasswordAuth::extract_username(&req);
    assert!(username.is_none());
  }

  // ============== verify_and_extract_username tests ==============

  #[test]
  fn test_verify_and_extract_username_valid() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    let credentials = BASE64_STANDARD.encode("admin:secret123");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();

    let result = auth.verify_and_extract_username(&req);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("admin".to_string()));
  }

  #[test]
  fn test_verify_and_extract_username_invalid_credentials() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    let credentials = BASE64_STANDARD.encode("admin:wrongpassword");
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .header("Proxy-Authorization", format!("Basic {}", credentials))
      .body(())
      .unwrap();

    let result = auth.verify_and_extract_username(&req);
    assert!(result.is_err());
  }

  #[test]
  fn test_verify_and_extract_username_no_auth_configured() {
    let auth = UserPasswordAuth::none();

    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();

    let result = auth.verify_and_extract_username(&req);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
  }

  #[test]
  fn test_verify_and_extract_username_missing_header() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth = UserPasswordAuth::from_config(&config);

    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com")
      .body(())
      .unwrap();

    let result = auth.verify_and_extract_username(&req);
    assert!(result.is_err());
  }
}
