//! Plaintext password verification.

use std::collections::HashMap;

use crate::auth::AuthError;

/// Verify password against stored credentials.
pub fn verify_password(
  users: &HashMap<String, String>,
  username: &str,
  password: &str,
) -> Result<(), AuthError> {
  if username.is_empty() {
    return Err(AuthError::UserNotFound("".to_string()));
  }
  if password.is_empty() {
    return Err(AuthError::InvalidCredentials);
  }

  match users.get(username) {
    Some(stored_password) => {
      if stored_password == password {
        Ok(())
      } else {
        Err(AuthError::InvalidCredentials)
      }
    }
    None => Err(AuthError::UserNotFound(username.to_string())),
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
  fn test_verify_password_unknown_user() {
    let users = HashMap::new();
    let result = verify_password(&users, "unknown", "password");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::UserNotFound(_)));
  }

  #[test]
  fn test_verify_password_empty_username() {
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret".to_string());
    let result = verify_password(&users, "", "password");
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::UserNotFound(_)));
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
