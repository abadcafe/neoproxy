//! Black-box tests for the auth module.

use crate::auth::{AuthError, UserPasswordAuth};

fn user_credential(
  username: &str,
  password: &str,
) -> crate::config::UserCredential {
  serde_yaml::from_str(&format!(
    "username: {username:?}\npassword: {password:?}\n"
  ))
  .unwrap()
}

// ============== verify_credentials tests (for SOCKS5) ==============

#[test]
fn test_verify_credentials_valid() {
  let users = vec![user_credential("socks_user", "socks_pass")];
  let auth = UserPasswordAuth::from_users(&users);
  assert!(auth.verify_credentials("socks_user", "socks_pass").is_ok());
}

#[test]
fn test_verify_credentials_invalid() {
  let users = vec![user_credential("socks_user", "socks_pass")];
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
  let auth = UserPasswordAuth::from_users(&[user_credential(
    "admin",
    "secret123",
  )]);
  assert!(auth.verify_credentials("admin", "secret123").is_ok());
}

#[test]
fn test_verify_password_wrong_password() {
  let auth = UserPasswordAuth::from_users(&[user_credential(
    "admin",
    "secret123",
  )]);
  let result = auth.verify_credentials("admin", "wrongpassword");
  assert!(result.is_err());
  assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
}

#[test]
fn test_verify_password_unknown_user_returns_invalid_credentials() {
  let auth =
    UserPasswordAuth::from_users(&[user_credential("admin", "secret")]);
  let result = auth.verify_credentials("unknown", "password");
  assert!(result.is_err());
  assert!(
    matches!(result.unwrap_err(), AuthError::InvalidCredentials),
    "Unknown user should return InvalidCredentials, not UserNotFound"
  );
}

#[test]
fn test_verify_password_empty_username_returns_invalid_credentials() {
  let auth =
    UserPasswordAuth::from_users(&[user_credential("admin", "secret")]);
  let result = auth.verify_credentials("", "password");
  assert!(result.is_err());
  assert!(
    matches!(result.unwrap_err(), AuthError::InvalidCredentials),
    "Empty username should return InvalidCredentials"
  );
}

#[test]
fn test_verify_password_empty_password() {
  let auth =
    UserPasswordAuth::from_users(&[user_credential("admin", "secret")]);
  let result = auth.verify_credentials("admin", "");
  assert!(result.is_err());
  assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
}

// ============== parse_basic_auth tests ==============

#[test]
fn test_parse_basic_auth_valid() {
  use base64::Engine;
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
  let header = http::HeaderValue::from_str("Bearer token123").unwrap();
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
  use base64::Engine;
  use base64::engine::general_purpose::STANDARD as BASE64;
  let credentials = BASE64.encode("nocolon");
  let header =
    http::HeaderValue::from_str(&format!("Basic {}", credentials))
      .unwrap();
  assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
}

#[test]
fn test_parse_basic_auth_empty_username() {
  use base64::Engine;
  use base64::engine::general_purpose::STANDARD as BASE64;
  let credentials = BASE64.encode(":password");
  let header =
    http::HeaderValue::from_str(&format!("Basic {}", credentials))
      .unwrap();
  assert!(UserPasswordAuth::parse_basic_auth(&header).is_err());
}

#[test]
fn test_parse_basic_auth_empty_password() {
  use base64::Engine;
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
  use base64::Engine;
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
