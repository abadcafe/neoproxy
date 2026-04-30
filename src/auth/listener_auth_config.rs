//! Listener authentication configuration.
//!
//! This module defines the unified authentication configuration for all listeners.
//! Field presence determines auth type — no `type` YAML field needed:
//! - `users` non-empty → password authentication
//! - `client_ca_path` present → TLS client certificate authentication
//! - Both present → dual-factor AND authentication

use serde::Deserialize;
use std::collections::HashMap;

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
/// - `users` non-empty → password authentication (UserPasswordAuth)
/// - `client_ca_path` present → TLS client cert authentication (ClientCertAuth)
/// - Both present → dual-factor AND authentication
///
/// At least one field must be configured. `auth: {}` (both empty) is invalid.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct ListenerAuthConfig {
  /// User credentials for password authentication.
  /// Non-empty → password auth enabled.
  /// Empty or missing → no password auth.
  #[serde(default)]
  pub users: Vec<UserCredential>,
  /// Client CA certificate path for TLS client cert authentication.
  /// Present → cert auth enabled.
  #[serde(default)]
  pub client_ca_path: Option<String>,
}

impl ListenerAuthConfig {
  /// Get users as a HashMap for password lookup.
  ///
  /// Returns `None` if no users are configured (empty array).
  pub fn users_map(&self) -> Option<HashMap<String, String>> {
    if self.users.is_empty() {
      None
    } else {
      Some(
        self
          .users
          .iter()
          .map(|u| (u.username.clone(), u.password.clone()))
          .collect(),
      )
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config_validator::{
    ConfigErrorCollector, validate_listener_auth_config,
  };

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
    assert!(!config.users.is_empty());
    assert!(config.client_ca_path.is_none());
    assert_eq!(config.users[0].username, "admin");
  }

  #[test]
  fn test_listener_auth_config_tls_only() {
    let yaml = r#"
client_ca_path: /path/to/ca.pem
"#;
    let config: ListenerAuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(config.users.is_empty());
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
    assert!(!config.users.is_empty());
    assert!(config.client_ca_path.is_some());
  }

  #[test]
  fn test_listener_auth_config_empty_users_with_tls_is_valid() {
    // users: [] + client_ca_path should be valid (TLS-only auth)
    let yaml = r#"
users: []
client_ca_path: /path/to/ca.pem
"#;
    let config: ListenerAuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(config.users.is_empty());
    assert!(config.client_ca_path.is_some());
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors(), "Empty users with TLS should be valid");
  }

  #[test]
  fn test_listener_auth_config_validate_empty_is_error() {
    let config = ListenerAuthConfig::default();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors(), "Empty auth config should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_duplicate_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![
        UserCredential {
          username: "admin".to_string(),
          password: "pass1".to_string(),
        },
        UserCredential {
          username: "admin".to_string(),
          password: "pass2".to_string(),
        },
      ],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors(), "Duplicate usernames should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_empty_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "".to_string(),
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors(), "Empty username should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_long_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "a".repeat(256),
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors(), "Username > 255 bytes should be invalid");
  }

  #[test]
  fn test_listener_auth_config_validate_password_only_ok() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_listener_auth_config_validate_tls_only_ok() {
    let config = ListenerAuthConfig {
      users: vec![],
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_listener_auth_config_validate_dual_factor_ok() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }],
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_users_map_returns_hashmap() {
    let config = ListenerAuthConfig {
      users: vec![
        UserCredential {
          username: "admin".to_string(),
          password: "secret123".to_string(),
        },
        UserCredential {
          username: "user2".to_string(),
          password: "pass456".to_string(),
        },
      ],
      client_ca_path: None,
    };
    let map = config.users_map().expect("should return Some");
    assert_eq!(map.get("admin"), Some(&"secret123".to_string()));
    assert_eq!(map.get("user2"), Some(&"pass456".to_string()));
  }

  #[test]
  fn test_users_map_returns_none_when_no_users() {
    let config = ListenerAuthConfig {
      users: vec![],
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    assert!(config.users_map().is_none());
  }
}
