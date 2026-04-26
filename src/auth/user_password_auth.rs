//! User/password authentication (HTTP application layer + SOCKS5).
//!
//! Handles HTTP Proxy-Authorization header verification and direct
//! username/password verification for SOCKS5.

use std::collections::HashMap;

use base64::{
  Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
};
use subtle::ConstantTimeEq;
use tracing::debug;

use crate::auth::AuthError;
use crate::auth::ListenerAuthConfig;

/// Verify password against stored credentials using constant-time comparison.
///
/// All authentication failures return `AuthError::InvalidCredentials` to avoid
/// leaking information about whether a username exists (CR-009).
fn verify_password(
  users: &HashMap<String, String>,
  username: &str,
  password: &str,
) -> Result<(), AuthError> {
  if username.is_empty() || password.is_empty() {
    return Err(AuthError::InvalidCredentials);
  }

  match users.get(username) {
    Some(stored_password) => {
      // CR-009: Use constant-time comparison to prevent timing attacks
      if stored_password.as_bytes().ct_eq(password.as_bytes()).into() {
        Ok(())
      } else {
        Err(AuthError::InvalidCredentials)
      }
    }
    None => {
      // CR-009: Return InvalidCredentials (not UserNotFound) to avoid
      // leaking information about whether a username exists
      Err(AuthError::InvalidCredentials)
    }
  }
}

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
}

#[cfg(test)]
mod tests {
  use super::*;
  use base64::{
    Engine, engine::general_purpose::STANDARD as BASE64_STANDARD,
  };

  // ============== verify_credentials tests (for SOCKS5) ==============

  #[test]
  fn test_verify_credentials_valid() {
    let config =
      crate::auth::ListenerAuthConfig {
        users: vec![
          crate::auth::UserCredential {
            username: "socks_user".to_string(),
            password: "socks_pass".to_string(),
          },
        ],
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
      crate::auth::ListenerAuthConfig {
        users: vec![
          crate::auth::UserCredential {
            username: "socks_user".to_string(),
            password: "socks_pass".to_string(),
          },
        ],
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

  // ============== verify_and_extract_username tests ==============

  #[test]
  fn test_verify_and_extract_username_valid() {
    let config =
      crate::auth::ListenerAuthConfig {
        users: vec![
          crate::auth::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ],
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
      crate::auth::ListenerAuthConfig {
        users: vec![
          crate::auth::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ],
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
      crate::auth::ListenerAuthConfig {
        users: vec![
          crate::auth::UserCredential {
            username: "admin".to_string(),
            password: "secret123".to_string(),
          },
        ],
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

  // ============== verify_password tests (from password.rs) ==============

  #[test]
  fn test_verify_password_success() {
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret123".to_string());
    let result = verify_password(&users, "admin", "secret123");
    assert!(result.is_ok());
  }

  #[test]
  fn test_verify_password_wrong_password() {
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret123".to_string());
    let result = verify_password(&users, "admin", "wrongpassword");
    assert!(result.is_err());
    assert!(matches!(
      result.unwrap_err(),
      AuthError::InvalidCredentials
    ));
  }

  #[test]
  fn test_verify_password_unknown_user_returns_invalid_credentials() {
    // CR-009: Unknown user should return InvalidCredentials (same as wrong password)
    let users = HashMap::new();
    let result = verify_password(&users, "unknown", "password");
    assert!(result.is_err());
    assert!(
      matches!(result.unwrap_err(), AuthError::InvalidCredentials),
      "Unknown user should return InvalidCredentials, not UserNotFound"
    );
  }

  #[test]
  fn test_verify_password_empty_username_returns_invalid_credentials() {
    // CR-009: Empty username should return InvalidCredentials
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret".to_string());
    let result = verify_password(&users, "", "password");
    assert!(result.is_err());
    assert!(
      matches!(result.unwrap_err(), AuthError::InvalidCredentials),
      "Empty username should return InvalidCredentials"
    );
  }

  #[test]
  fn test_verify_password_empty_password() {
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret".to_string());
    let result = verify_password(&users, "admin", "");
    assert!(result.is_err());
    assert!(matches!(
      result.unwrap_err(),
      AuthError::InvalidCredentials
    ));
  }
}
