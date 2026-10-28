//! module: auth
//! responsibility: parse and verify proxy credentials
//! public operations: AuthError, UserPasswordAuth, none, from_users,
//! verify_credentials, parse_basic_auth
//! data entities: AuthError, UserPasswordAuth
//! tests: auth_tests.rs

//! Shared authentication types.
//!
//! Contains credential types and verification for request middleware.
//! Protocol adapters only collect credentials. The shared request
//! middleware is the sole verifier for both HTTP and converted SOCKS5
//! CONNECT requests.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use subtle::ConstantTimeEq;

use crate::redaction::Redacted;

/// Authentication error types.
#[derive(Debug, Clone)]
pub(crate) enum AuthError {
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
  if username.is_empty() {
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
/// Handles HTTP Basic and typed credentials from converted SOCKS5
/// requests. Verification takes place in request middleware.
/// When users are configured, authentication is REQUIRED.
#[derive(Clone)]
pub(crate) struct UserPasswordAuth {
  users: Option<Arc<HashMap<String, String>>>,
}

impl std::fmt::Debug for UserPasswordAuth {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("UserPasswordAuth")
      .field("users", &self.users.as_deref().map(Redacted))
      .finish()
  }
}

impl UserPasswordAuth {
  /// Create a UserPasswordAuth with no verification (no password
  /// required).
  pub(crate) fn none() -> Self {
    Self { users: None }
  }

  /// Build from a slice of UserCredential.
  ///
  /// Creates a verifier with the configured users.
  /// Pure memory operation, cannot fail.
  pub(crate) fn from_users(
    users: &[crate::config::UserCredential],
  ) -> Self {
    if users.is_empty() {
      Self::none()
    } else {
      let map = users
        .iter()
        .map(|u| (u.username().to_string(), u.password().to_string()))
        .collect();
      Self { users: Some(Arc::new(map)) }
    }
  }

  /// Verify username/password directly (for SOCKS5).
  ///
  /// Returns Ok(()) if authentication succeeds or no auth is
  /// configured.
  pub(crate) fn verify_credentials(
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

    let (scheme, encoded) =
      header_str.split_once(' ').ok_or_else(|| {
        AuthError::ConfigError("Missing authentication scheme".into())
      })?;
    if !scheme.eq_ignore_ascii_case("Basic") {
      return Err(AuthError::ConfigError(
        "Not Basic authentication".into(),
      ));
    }
    let encoded = encoded.trim_start_matches(' ');
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
