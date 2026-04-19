//! Plaintext password verification.

use std::collections::HashMap;

use subtle::ConstantTimeEq;

use crate::auth::AuthError;

/// Verify password against stored credentials using constant-time comparison.
///
/// All authentication failures return `AuthError::InvalidCredentials` to avoid
/// leaking information about whether a username exists (CR-009).
pub fn verify_password(
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

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;

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
    // to avoid leaking information about whether a username exists
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
      "Empty username should return InvalidCredentials, not UserNotFound"
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
