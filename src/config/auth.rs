//! Authentication configuration types and validation.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use super::{ConfigErrorCollector, ConfigErrorKind};

/// User credential configuration
#[derive(Deserialize, Clone, Debug)]
pub struct UserConfig {
  /// Username for authentication
  pub username: String,
  /// Password for authentication
  pub password: String,
}

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
/// - `users` non-empty → password authentication
/// - `client_ca_path` present → TLS client cert authentication
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

  #[test]
  fn test_user_config_deserialize() {
    let yaml = r#"
username: "admin"
password: "secret"
"#;
    let user: UserConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(user.username, "admin");
    assert_eq!(user.password, "secret");
  }

  #[test]
  fn test_listener_auth_config_users_map() {
    let config = ListenerAuthConfig {
      users: vec![
        UserCredential {
          username: "admin".to_string(),
          password: "pass1".to_string(),
        },
        UserCredential {
          username: "user".to_string(),
          password: "pass2".to_string(),
        },
      ],
      client_ca_path: None,
    };
    let map = config.users_map().unwrap();
    assert_eq!(map.get("admin"), Some(&"pass1".to_string()));
    assert_eq!(map.get("user"), Some(&"pass2".to_string()));
  }

  #[test]
  fn test_listener_auth_config_empty_users_map() {
    let config = ListenerAuthConfig::default();
    assert!(config.users_map().is_none());
  }
}

// =========================================================================
// Validation logic
// =========================================================================

/// Validate server-level users configuration.
pub fn validate_users(
  users: &[UserConfig],
  location: &str,
  collector: &mut ConfigErrorCollector,
) {
  if users.is_empty() {
    collector.add(
      location.to_string(),
      "users cannot be an empty array".to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  for (idx, user) in users.iter().enumerate() {
    let user_location = format!("{}[{}]", location, idx);

    if user.username.is_empty() {
      collector.add(
        format!("{}.username", user_location),
        "username cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if user.password.is_empty() {
      collector.add(
        format!("{}.password", user_location),
        "password cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }
}

/// Validate listener authentication configuration.
///
/// Rules:
/// - At least one auth method (`users` or `client_ca_path`) must be configured
/// - Each username must be non-empty, <= 255 bytes, and unique
pub fn validate_listener_auth_config(
  auth: &ListenerAuthConfig,
  collector: &mut ConfigErrorCollector,
) {
  // At least one auth method must be configured
  if auth.users.is_empty() && auth.client_ca_path.is_none() {
    collector.add(
      "auth",
      "auth config must have at least 'users' or 'client_ca_path'"
        .to_string(),
      ConfigErrorKind::InvalidFormat,
    );
    return;
  }

  // Validate users
  let mut seen_users = HashSet::new();
  for (idx, user) in auth.users.iter().enumerate() {
    let user_location = format!("auth.users[{}]", idx);

    if user.username.is_empty() {
      collector.add(
        format!("{}.username", user_location),
        "username cannot be empty".to_string(),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if user.username.len() > 255 {
      collector.add(
        format!("{}.username", user_location),
        format!(
          "username '{}' is too long (max 255 bytes)",
          user.username
        ),
        ConfigErrorKind::InvalidFormat,
      );
    }

    if !seen_users.insert(user.username.clone()) {
      collector.add(
        format!("{}.username", user_location),
        format!(
          "duplicate username '{}' found in users list",
          user.username
        ),
        ConfigErrorKind::InvalidFormat,
      );
    }
  }
}

#[cfg(test)]
mod validation_tests {
  use super::*;

  #[test]
  fn test_validate_users_valid() {
    let users = vec![UserConfig {
      username: "admin".to_string(),
      password: "secret".to_string(),
    }];
    let mut collector = ConfigErrorCollector::new();
    validate_users(&users, "servers[0].users", &mut collector);
    assert!(
      !collector.has_errors(),
      "Valid users should pass: {:?}",
      collector.errors()
    );
  }

  #[test]
  fn test_validate_users_empty_array() {
    let users: Vec<UserConfig> = vec![];
    let mut collector = ConfigErrorCollector::new();
    validate_users(&users, "servers[0].users", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("users cannot be an empty array"));
    assert!(found);
  }

  #[test]
  fn test_validate_users_empty_username() {
    let users = vec![UserConfig {
      username: "".to_string(),
      password: "secret".to_string(),
    }];
    let mut collector = ConfigErrorCollector::new();
    validate_users(&users, "servers[0].users", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("username cannot be empty"));
    assert!(found);
  }

  #[test]
  fn test_validate_users_empty_password() {
    let users = vec![UserConfig {
      username: "admin".to_string(),
      password: "".to_string(),
    }];
    let mut collector = ConfigErrorCollector::new();
    validate_users(&users, "servers[0].users", &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("password cannot be empty"));
    assert!(found);
  }

  #[test]
  fn test_validate_listener_auth_config_empty_is_error() {
    let config = ListenerAuthConfig::default();
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector.errors().iter().any(|e| {
      e.message
        .contains("must have at least 'users' or 'client_ca_path'")
    });
    assert!(found);
  }

  #[test]
  fn test_validate_listener_auth_config_password_only_ok() {
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
  fn test_validate_listener_auth_config_tls_only_ok() {
    let config = ListenerAuthConfig {
      users: vec![],
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(!collector.has_errors());
  }

  #[test]
  fn test_validate_listener_auth_config_duplicate_username_is_error() {
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
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("duplicate username"));
    assert!(found);
  }

  #[test]
  fn test_validate_listener_auth_config_empty_username_is_error() {
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: "".to_string(),
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("username cannot be empty"));
    assert!(found);
  }

  #[test]
  fn test_validate_listener_auth_config_username_too_long() {
    let long_username = "a".repeat(256);
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: long_username,
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(collector.has_errors());
    let found = collector
      .errors()
      .iter()
      .any(|e| e.message.contains("is too long"));
    assert!(found);
  }

  #[test]
  fn test_validate_listener_auth_config_username_255_ok() {
    let username_255 = "a".repeat(255);
    let config = ListenerAuthConfig {
      users: vec![UserCredential {
        username: username_255,
        password: "pass".to_string(),
      }],
      client_ca_path: None,
    };
    let mut collector = ConfigErrorCollector::new();
    validate_listener_auth_config(&config, &mut collector);
    assert!(
      !collector.has_errors(),
      "255-byte username should be valid: {:?}",
      collector.errors()
    );
  }
}
