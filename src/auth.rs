//! Shared authentication types.
//!
//! Contains `UserPasswordAuth` and `AuthError` used by both the
//! listener layer (SOCKS5 handshake) and the plugin layer (HTTP Basic
//! Auth).

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use subtle::ConstantTimeEq;

/// Authentication error types.
#[derive(Debug, Clone)]
pub enum AuthError {
  /// Invalid username or password.
  /// CR-009: All authentication failures return this variant to avoid
  /// leaking information about whether a username exists.
  InvalidCredentials,
  /// Configuration error.
  ConfigError(String),
}

impl std::fmt::Display for AuthError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidCredentials => write!(f, "invalid credentials"),
      Self::ConfigError(msg) => write!(f, "auth config error: {}", msg),
    }
  }
}

impl std::error::Error for AuthError {}

/// Verify password against stored credentials using constant-time
/// comparison.
///
/// All authentication failures return `AuthError::InvalidCredentials`
/// to avoid leaking information about whether a username exists
/// (CR-009).
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
  /// Create a UserPasswordAuth with no verification (no password
  /// required).
  pub fn none() -> Self {
    Self { users: None }
  }

  /// Build from a slice of UserCredential.
  ///
  /// Creates a verifier with the configured users.
  /// Pure memory operation, cannot fail.
  pub fn from_users(users: &[crate::config::UserCredential]) -> Self {
    if users.is_empty() {
      Self::none()
    } else {
      let map = users
        .iter()
        .map(|u| (u.username.clone(), u.password.clone()))
        .collect();
      Self { users: Some(map) }
    }
  }

  /// Verify username/password directly (for SOCKS5).
  ///
  /// Returns Ok(()) if authentication succeeds or no auth is
  /// configured.
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
  pub(crate) fn parse_basic_auth(
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

  // ============== verify_credentials tests (for SOCKS5) ==============

  #[test]
  fn test_verify_credentials_valid() {
    let users = vec![crate::config::UserCredential {
      username: "socks_user".to_string(),
      password: "socks_pass".to_string(),
    }];
    let auth = UserPasswordAuth::from_users(&users);
    assert!(
      auth.verify_credentials("socks_user", "socks_pass").is_ok()
    );
  }

  #[test]
  fn test_verify_credentials_invalid() {
    let users = vec![crate::config::UserCredential {
      username: "socks_user".to_string(),
      password: "socks_pass".to_string(),
    }];
    let auth = UserPasswordAuth::from_users(&users);
    assert!(auth.verify_credentials("socks_user", "wrong").is_err());
  }

  #[test]
  fn test_verify_credentials_no_users_configured() {
    let auth = UserPasswordAuth::none();
    // No users configured -> verify_credentials always passes
    assert!(auth.verify_credentials("anyone", "anything").is_ok());
  }

  // ============== verify_password tests ==============

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

  // ============== parse_basic_auth tests ==============

  #[test]
  fn test_parse_basic_auth_valid() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    let credentials = BASE64.encode("admin:secret");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      UserPasswordAuth::parse_basic_auth(&header).unwrap();
    assert_eq!(user, "admin");
    assert_eq!(pass, "secret");
  }

  #[test]
  fn test_parse_basic_auth_no_basic_prefix() {
    let header =
      http::HeaderValue::from_str("Bearer token123").unwrap();
    assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
  }

  #[test]
  fn test_parse_basic_auth_invalid_base64() {
    let header =
      http::HeaderValue::from_str("Basic not-valid-base64!!!").unwrap();
    assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
  }

  #[test]
  fn test_parse_basic_auth_no_colon() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    let credentials = BASE64.encode("nocolon");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
  }

  #[test]
  fn test_parse_basic_auth_empty_username() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    let credentials = BASE64.encode(":password");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
  }

  #[test]
  fn test_parse_basic_auth_empty_password() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    let credentials = BASE64.encode("user:");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      UserPasswordAuth::parse_basic_auth(&header).unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "");
  }

  #[test]
  fn test_parse_basic_auth_password_with_colon() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    let credentials = BASE64.encode("user:pass:word");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      UserPasswordAuth::parse_basic_auth(&header).unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "pass:word");
  }
}
