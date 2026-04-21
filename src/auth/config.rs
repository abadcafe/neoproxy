//! Authentication configuration structures.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::auth::AuthError;

/// Authentication type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
  /// Password authentication with username/password.
  Password,
  /// TLS client certificate authentication.
  TlsClientCert,
}

/// User credential for password authentication.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserCredential {
  /// Username.
  pub username: String,
  /// Password (plaintext).
  pub password: String,
}

/// Authentication configuration for a single auth method.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
  /// Authentication type.
  #[serde(rename = "type")]
  pub auth_type: AuthType,
  /// User credentials for password authentication.
  #[serde(default)]
  pub users: Option<Vec<UserCredential>>,
  /// Client CA certificate path for TLS client cert authentication.
  #[serde(default)]
  pub client_ca_path: Option<String>,
}

/// Multi-auth configuration that supports multiple authentication methods.
///
/// This is used by listeners that need to support multiple auth methods
/// simultaneously (e.g., mTLS + password fallback).
#[derive(Debug, Clone, Default)]
pub struct MultiAuthConfig {
  /// List of authentication configurations.
  /// When multiple auth methods are configured, they are tried in order.
  pub configs: Vec<AuthConfig>,
}

impl AuthConfig {
  /// Validate authentication configuration.
  pub fn validate(
    &self,
    supported_types: &[AuthType],
  ) -> Result<(), AuthError> {
    if !supported_types.contains(&self.auth_type) {
      let type_str = match self.auth_type {
        AuthType::Password => "password",
        AuthType::TlsClientCert => "tls_client_cert",
      };
      return Err(AuthError::UnsupportedAuthType(type_str.to_string()));
    }

    match self.auth_type {
      AuthType::Password => {
        if self.users.is_none() {
          return Err(AuthError::ConfigError(
            "users is required for password authentication".to_string(),
          ));
        }
        let users = self.users.as_ref().unwrap();
        if users.is_empty() {
          return Err(AuthError::ConfigError(
            "users cannot be empty for password authentication"
              .to_string(),
          ));
        }
        // Check for duplicate usernames (CR-001)
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
        if self.client_ca_path.is_some() {
          return Err(AuthError::ConfigError(
                        "client_ca_path should not be configured for password authentication"
                            .to_string(),
                    ));
        }
        Ok(())
      }
      AuthType::TlsClientCert => {
        if self.client_ca_path.is_none() {
          return Err(AuthError::ConfigError(
                        "client_ca_path is required for tls_client_cert authentication"
                            .to_string(),
                    ));
        }
        if self.users.is_some() {
          return Err(AuthError::ConfigError(
                        "users should not be configured for tls_client_cert authentication"
                            .to_string(),
                    ));
        }
        Ok(())
      }
    }
  }

  /// Create a validated AuthConfig from YAML value.
  pub fn from_yaml(
    yaml: serde_yaml::Value,
    supported_types: &[AuthType],
  ) -> Result<Self, AuthError> {
    let config: Self = serde_yaml::from_value(yaml).map_err(|e| {
      AuthError::ConfigError(format!(
        "failed to parse auth config: {}",
        e
      ))
    })?;
    config.validate(supported_types)?;
    Ok(config)
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

impl MultiAuthConfig {
  /// Create a validated MultiAuthConfig from YAML value.
  ///
  /// Accepts both a single auth config object and an array of auth configs.
  pub fn from_yaml(
    yaml: serde_yaml::Value,
    supported_types: &[AuthType],
  ) -> Result<Self, AuthError> {
    // Try to parse as an array first
    let configs: Vec<AuthConfig> = if yaml.is_sequence() {
      serde_yaml::from_value(yaml).map_err(|e| {
        AuthError::ConfigError(format!("failed to parse auth config array: {}", e))
      })?
    } else {
      // Parse as a single auth config
      let config: AuthConfig = serde_yaml::from_value(yaml).map_err(|e| {
        AuthError::ConfigError(format!("failed to parse auth config: {}", e))
      })?;
      vec![config]
    };

    // Validate each config
    for config in &configs {
      config.validate(supported_types)?;
    }

    Ok(Self { configs })
  }

  /// Check if any auth config uses TLS client cert authentication.
  pub fn has_tls_client_cert(&self) -> bool {
    self.configs.iter().any(|c| c.auth_type == AuthType::TlsClientCert)
  }

  /// Check if any auth config uses password authentication.
  pub fn has_password(&self) -> bool {
    self.configs.iter().any(|c| c.auth_type == AuthType::Password)
  }

  /// Get the client CA path for TLS client cert authentication.
  /// Returns the first client_ca_path found in the config list.
  pub fn client_ca_pathbuf(&self) -> Option<PathBuf> {
    self.configs.iter().find_map(|c| c.client_ca_pathbuf())
  }

  /// Get users as a HashMap for password lookup.
  /// Merges users from all password auth configs.
  pub fn users_map(&self) -> Option<HashMap<String, String>> {
    let mut result = HashMap::new();
    for config in &self.configs {
      if let Some(users) = config.users_map() {
        result.extend(users);
      }
    }
    if result.is_empty() {
      None
    } else {
      Some(result)
    }
  }

  /// Check if authentication is required (any auth configured).
  pub fn is_auth_required(&self) -> bool {
    !self.configs.is_empty()
  }

  /// Check if this is a multi-auth configuration (more than one auth method).
  pub fn is_multi_auth(&self) -> bool {
    self.configs.len() > 1
  }

  /// Validate the multi-auth configuration for logical consistency.
  pub fn validate(&self) -> Result<(), AuthError> {
    // Check that we have at least one config if this is called
    if self.configs.is_empty() {
      return Ok(());
    }

    // For multi-auth with both TLS client cert and password,
    // the configuration is valid - TLS cert will be optional at handshake,
    // and authentication will be checked at HTTP level.

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_auth_config_password_type() {
    let yaml = r#"
type: password
users:
  - username: admin
    password: secret123
"#;
    let config: AuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(matches!(config.auth_type, AuthType::Password));
    assert!(config.users.is_some());
    let users = config.users.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "admin");
    assert_eq!(users[0].password, "secret123");
  }

  #[test]
  fn test_auth_config_tls_client_cert_type() {
    let yaml = r#"
type: tls_client_cert
client_ca_path: /path/to/client_ca.pem
"#;
    let config: AuthConfig =
      serde_yaml::from_str(yaml).expect("parse failed");
    assert!(matches!(config.auth_type, AuthType::TlsClientCert));
    assert!(config.client_ca_path.is_some());
    assert_eq!(
      config.client_ca_path.unwrap(),
      "/path/to/client_ca.pem"
    );
  }

  #[test]
  fn test_auth_config_validate_password_success() {
    let config = AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    };
    let result =
      config.validate(&[AuthType::Password, AuthType::TlsClientCert]);
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_validate_password_missing_users() {
    let config = AuthConfig {
      auth_type: AuthType::Password,
      users: None,
      client_ca_path: None,
    };
    let result =
      config.validate(&[AuthType::Password, AuthType::TlsClientCert]);
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_validate_tls_client_cert_success() {
    let config = AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let result =
      config.validate(&[AuthType::Password, AuthType::TlsClientCert]);
    assert!(result.is_ok());
  }

  #[test]
  fn test_auth_config_validate_tls_client_cert_missing_path() {
    let config = AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: None,
    };
    let result =
      config.validate(&[AuthType::Password, AuthType::TlsClientCert]);
    assert!(result.is_err());
  }

  #[test]
  fn test_auth_config_validate_unsupported_type_for_socks5() {
    let config = AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let result = config.validate(&[AuthType::Password]);
    assert!(result.is_err());
    assert!(matches!(
      result.unwrap_err(),
      AuthError::UnsupportedAuthType(_)
    ));
  }

  #[test]
  fn test_users_map_returns_hashmap() {
    let config = AuthConfig {
      auth_type: AuthType::Password,
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
    let map = config.users_map().expect("users_map should return Some");
    assert_eq!(map.get("admin"), Some(&"secret123".to_string()));
    assert_eq!(map.get("user2"), Some(&"pass456".to_string()));
    assert_eq!(map.get("nonexistent"), None);
  }

  #[test]
  fn test_users_map_returns_none_for_no_users() {
    let config = AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    assert!(config.users_map().is_none());
  }

  #[test]
  fn test_client_ca_pathbuf_returns_pathbuf() {
    let config = AuthConfig {
      auth_type: AuthType::TlsClientCert,
      users: None,
      client_ca_path: Some("/path/to/ca.pem".to_string()),
    };
    let path = config.client_ca_pathbuf().expect("should return Some");
    assert_eq!(path, std::path::PathBuf::from("/path/to/ca.pem"));
  }

  #[test]
  fn test_client_ca_pathbuf_returns_none_for_no_path() {
    let config = AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }]),
      client_ca_path: None,
    };
    assert!(config.client_ca_pathbuf().is_none());
  }

  #[test]
  fn test_validate_duplicate_username_returns_error() {
    // CR-001: Duplicate usernames should be detected and rejected
    let config = AuthConfig {
      auth_type: AuthType::Password,
      users: Some(vec![
        UserCredential {
          username: "admin".to_string(),
          password: "secret123".to_string(),
        },
        UserCredential {
          username: "admin".to_string(), // duplicate username
          password: "different456".to_string(),
        },
      ]),
      client_ca_path: None,
    };
    let result =
      config.validate(&[AuthType::Password, AuthType::TlsClientCert]);
    assert!(
      result.is_err(),
      "duplicate usernames should cause validation error"
    );
    let err = result.unwrap_err();
    assert!(matches!(err, AuthError::ConfigError(_)));
    assert!(err.to_string().contains("duplicate"));
  }

  // ============== MultiAuthConfig Tests ==============

  #[test]
  fn test_multi_auth_config_from_yaml_single() {
    let yaml = r#"
type: password
users:
  - username: admin
    password: secret123
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config = MultiAuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    )
    .expect("parse multi auth config");
    assert_eq!(config.configs.len(), 1);
    assert!(config.has_password());
    assert!(!config.has_tls_client_cert());
    assert!(!config.is_multi_auth());
  }

  #[test]
  fn test_multi_auth_config_from_yaml_array() {
    let yaml = r#"
- type: tls_client_cert
  client_ca_path: /path/to/ca.pem
- type: password
  users:
    - username: admin
      password: secret123
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).expect("parse yaml");
    let config = MultiAuthConfig::from_yaml(
      yaml_value,
      &[AuthType::Password, AuthType::TlsClientCert],
    )
    .expect("parse multi auth config");
    assert_eq!(config.configs.len(), 2);
    assert!(config.has_password());
    assert!(config.has_tls_client_cert());
    assert!(config.is_multi_auth());
  }

  #[test]
  fn test_multi_auth_config_has_methods() {
    let config = MultiAuthConfig {
      configs: vec![
        AuthConfig {
          auth_type: AuthType::TlsClientCert,
          users: None,
          client_ca_path: Some("/path/to/ca.pem".to_string()),
        },
        AuthConfig {
          auth_type: AuthType::Password,
          users: Some(vec![UserCredential {
            username: "admin".to_string(),
            password: "secret".to_string(),
          }]),
          client_ca_path: None,
        },
      ],
    };
    assert!(config.has_tls_client_cert());
    assert!(config.has_password());
    assert!(config.is_auth_required());
    assert!(config.is_multi_auth());
  }

  #[test]
  fn test_multi_auth_config_users_map_merges() {
    let config = MultiAuthConfig {
      configs: vec![
        AuthConfig {
          auth_type: AuthType::Password,
          users: Some(vec![UserCredential {
            username: "user1".to_string(),
            password: "pass1".to_string(),
          }]),
          client_ca_path: None,
        },
        AuthConfig {
          auth_type: AuthType::Password,
          users: Some(vec![UserCredential {
            username: "user2".to_string(),
            password: "pass2".to_string(),
          }]),
          client_ca_path: None,
        },
      ],
    };
    let map = config.users_map().expect("should have users");
    assert_eq!(map.get("user1"), Some(&"pass1".to_string()));
    assert_eq!(map.get("user2"), Some(&"pass2".to_string()));
  }

  #[test]
  fn test_multi_auth_config_client_ca_pathbuf() {
    let config = MultiAuthConfig {
      configs: vec![
        AuthConfig {
          auth_type: AuthType::TlsClientCert,
          users: None,
          client_ca_path: Some("/path/to/ca.pem".to_string()),
        },
        AuthConfig {
          auth_type: AuthType::Password,
          users: Some(vec![UserCredential {
            username: "admin".to_string(),
            password: "secret".to_string(),
          }]),
          client_ca_path: None,
        },
      ],
    };
    let path = config.client_ca_pathbuf().expect("should have ca path");
    assert_eq!(path, std::path::PathBuf::from("/path/to/ca.pem"));
  }

  #[test]
  fn test_multi_auth_config_empty() {
    let config = MultiAuthConfig::default();
    assert!(!config.is_auth_required());
    assert!(!config.has_password());
    assert!(!config.has_tls_client_cert());
    assert!(!config.is_multi_auth());
    assert!(config.users_map().is_none());
    assert!(config.client_ca_pathbuf().is_none());
  }
}
