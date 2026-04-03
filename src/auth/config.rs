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

/// Authentication configuration.
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
}
