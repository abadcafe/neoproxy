//! Listener authentication configuration.
//!
//! This module defines the unified authentication configuration for all listeners.
//! Field presence determines auth type — no `type` YAML field needed:
//! - `users` present → password authentication
//! - `client_ca_path` present → TLS client certificate authentication
//! - Both present → dual-factor AND authentication

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::auth::AuthError;

/// User credential for password authentication.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserCredential {
  /// Username.
  pub username: String,
  /// Password (plaintext).
  pub password: String,
}

/// Listener authentication configuration.
///
/// Field presence determines auth type:
/// - `users` present → password authentication (UserPasswordAuth)
/// - `client_ca_path` present → TLS client cert authentication (ClientCertAuth)
/// - Both present → dual-factor AND authentication
///
/// At least one field must be present. `auth: {}` (both None) is invalid for listeners.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ListenerAuthConfig {
  /// User credentials for password authentication.
  /// Present → password auth enabled.
  #[serde(default)]
  pub users: Option<Vec<UserCredential>>,
  /// Client CA certificate path for TLS client cert authentication.
  /// Present → cert auth enabled.
  #[serde(default)]
  pub client_ca_path: Option<String>,
}

impl ListenerAuthConfig {
  /// Validate the configuration.
  ///
  /// Rules:
  /// - `users` and `client_ca_path` at least one must be present
  /// - `users` cannot be empty array
  /// - Each username must be non-empty, <= 255 bytes, and unique
  pub fn validate(&self) -> Result<(), AuthError> {
    // At least one auth method must be configured
    if self.users.is_none() && self.client_ca_path.is_none() {
      return Err(AuthError::ConfigError(
        "auth config must have at least 'users' or 'client_ca_path'"
          .to_string(),
      ));
    }

    // Validate users if present
    if let Some(ref users) = self.users {
      if users.is_empty() {
        return Err(AuthError::ConfigError(
          "users cannot be empty for password authentication"
            .to_string(),
        ));
      }

      let mut seen_users = std::collections::HashSet::new();
      for user in users {
        if user.username.is_empty() {
          return Err(AuthError::ConfigError(
            "username cannot be empty".to_string(),
          ));
        }
        if user.username.len() > 255 {
          return Err(AuthError::ConfigError(format!(
            "username '{}' is too long (max 255 bytes)",
            user.username
          )));
        }
        if seen_users.contains(&user.username) {
          return Err(AuthError::ConfigError(format!(
            "duplicate username '{}' found in users list",
            user.username
          )));
        }
        seen_users.insert(user.username.clone());
      }
    }

    Ok(())
  }

  /// Get users as a HashMap for password lookup.
  pub fn users_map(&self) -> Option<HashMap<String, String>> {
    self.users.as_ref().map(|users| {
      users
        .iter()
        .map(|u| (u.username.clone(), u.password.clone()))
        .collect()
    })
  }

  /// Get client CA path as PathBuf.
  pub fn client_ca_pathbuf(&self) -> Option<PathBuf> {
    self.client_ca_path.as_ref().map(PathBuf::from)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // ============== UserCredential Tests ==============

  #[test]
  fn test_user_credential_deserialize() {
    let yaml = r#"
username: admin
password: secret123
"#;
    let cred: UserCredential =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert_eq!(cred.username, "admin");
    assert_eq!(cred.password, "secret123");
  }

  #[test]
  fn test_user_credential_equality() {
    let a = UserCredential {
      username: "admin".to_string(),
      password: "secret".to_string(),
    };
    let b = UserCredential {
      username: "admin".to_string(),
      password: "secret".to_string(),
    };
    assert_eq!(a, b);
  }

  // ============== ListenerAuthConfig Tests ==============

  #[test]
  fn test_listener_auth_config_password_only() {
    let yaml = r#"
users:
  - username: admin
    password: secret123
"#;
    let config: ListenerAuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(config.users.is_some());
    assert!(config.client_ca_path.is_none());
    let users = config.users.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "admin");
  }

  #[test]
  fn test_listener_auth_config_tls_only() {
    let yaml = r#"
client_ca_path: /path/to/ca.pem
"#;
    let config: ListenerAuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(config.users.is_none());
    assert!(config.client_ca_path.is_some());
    assert_eq!(config.client_ca_path.unwrap(), "/path/to/ca.pem");
  }

  #[test]
  fn test_listener_auth_config_dual_factor() {
    let yaml = r#"
users:
  - username: admin
    password: secret
client_ca_path: /path/to/ca.pem
"#;
    let config: ListenerAuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(config.users.is_some());
    assert!(config.client_ca_path.is_some());
  }

  #[test]
  fn test_listener_auth_config_validate_empty_is_error() {
    let config =
      ListenerAuthConfig { users: None, client_ca_path: None };
    let result = config.validate();
    assert!(result.is_err(), "Empty auth config should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_empty_users_is_error() {
    let config =
      ListenerAuthConfig { users: Some(vec![]), client_ca_path: None };
    let result = config.validate();
    assert!(result.is_err(), "Empty users array should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_duplicate_username_is_error() {
    let config = ListenerAuthConfig {
      users: Some(vec![
        UserCredential {
          username: "admin".to_string(),
          password: "pass1".to_string(),
        },
        UserCredential {
          username: "admin".to_string(),
          password: "pass2".to_string(),
        },
      ]),
      client_ca_path: None,
    };
    let result = config.validate();
    assert!(result.is_err(), "Duplicate usernames should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_empty_username_is_error() {
    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "".to_string(),
        password: "pass".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = config.validate();
    assert!(result.is_err(), "Empty username should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_long_username_is_error() {
    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "a".repeat(256),
        password: "pass".to_string(),
      }]),
      client_ca_path: None,
    };
    let result = config.validate();
    assert!(result.is_err(), "Username > 255 bytes should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_password_only_ok() {
    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    };
    assert!(config.validate().is_ok());
  }

  #[test]
  fn test_listener_auth_config_validate_tls_only_ok() {
    let config = ListenerAuthConfig {
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    assert!(config.validate().is_ok());
  }

  #[test]
  fn test_listener_auth_config_validate_dual_factor_ok() {
    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    assert!(config.validate().is_ok());
  }

  #[test]
  fn test_users_map_returns_hashmap() {
    let config = ListenerAuthConfig {
      users: Some(vec![
        UserCredential {
          username: "admin".to_string(),
          password: "secret123".to_string(),
        },
        UserCredential {
          username: "user2".to_string(),
          password: "pass456".to_string(),
        },
      ]),
      client_ca_path: None,
    };
    let map = config.users_map().expect("should return Some");
    assert_eq!(map.get("admin"), Some(&"secret123".to_string()));
    assert_eq!(map.get("user2"), Some(&"pass456".to_string()));
  }

  #[test]
  fn test_users_map_returns_none_when_no_users() {
    let config = ListenerAuthConfig {
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    assert!(config.users_map().is_none());
  }

  #[test]
  fn test_client_ca_pathbuf() {
    let config = ListenerAuthConfig {
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let path = config.client_ca_pathbuf().expect("should return Some");
    assert_eq!(path, PathBuf::from("/path/to/ca.pem"));
  }

  #[test]
  fn test_client_ca_pathbuf_returns_none() {
    let config = ListenerAuthConfig {
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    };
    assert!(config.client_ca_pathbuf().is_none());
  }
}
