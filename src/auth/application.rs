//! Application layer authentication (HTTP password).
//!
//! This module handles HTTP-level authentication independently from
//! transport-level authentication. When configured, password verification
//! is REQUIRED - failure means 407 Proxy Authentication Required.

use std::collections::HashMap;

use tracing::debug;

use crate::auth::config::MultiAuthConfig;
use crate::auth::{parse_basic_auth, verify_password, AuthError};

/// Application layer authenticator.
///
/// Handles HTTP Proxy-Authorization header verification.
/// When users are configured, password authentication is REQUIRED.
/// This is independent of transport-layer authentication.
#[derive(Debug, Clone)]
pub struct ApplicationAuth {
    users: Option<HashMap<String, String>>,
}

impl ApplicationAuth {
    /// Create an ApplicationAuth with no verification (no password required).
    pub fn none() -> Self {
        Self { users: None }
    }

    /// Create an ApplicationAuth with password verification.
    pub fn password(users: HashMap<String, String>) -> Self {
        Self { users: Some(users) }
    }

    /// Build from MultiAuthConfig.
    ///
    /// If the config includes `password` auth, creates a verifier with
    /// the configured users. Otherwise returns `none()`.
    pub fn from_config(config: &MultiAuthConfig) -> Self {
        match config.users_map() {
            Some(users) => Self::password(users),
            None => Self::none(),
        }
    }

    /// Whether application-layer authentication is required.
    #[allow(dead_code)]
    pub fn is_required(&self) -> bool {
        self.users.is_some()
    }

    /// Verify the HTTP request's Proxy-Authorization header.
    ///
    /// Returns Ok(()) if authentication succeeds or no auth is configured.
    /// Returns Err with appropriate AuthError otherwise.
    pub fn verify(&self, req: &http::Request<()>) -> Result<(), AuthError> {
        match &self.users {
            None => Ok(()),
            Some(users) => {
                let auth_header = req
                    .headers()
                    .get(http::header::PROXY_AUTHORIZATION)
                    .ok_or(AuthError::InvalidCredentials)?;
                let (username, password) = parse_basic_auth(auth_header)
                    .inspect_err(|e| {
                        debug!("Failed to parse Basic auth header: {}", e);
                    })
                    .map_err(|_| AuthError::InvalidCredentials)?;
                verify_password(users, &username, &password)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

    #[test]
    fn test_application_auth_none_is_not_required() {
        let auth = ApplicationAuth::none();
        assert!(!auth.is_required());
    }

    #[test]
    fn test_application_auth_none_always_passes() {
        let auth = ApplicationAuth::none();
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("http://example.com:443")
            .body(())
            .unwrap();
        assert!(auth.verify(&req).is_ok());
    }

    #[test]
    fn test_application_auth_password_is_required() {
        let mut users = std::collections::HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        let auth = ApplicationAuth::password(users);
        assert!(auth.is_required());
    }

    #[test]
    fn test_application_auth_password_valid_credentials() {
        let mut users = std::collections::HashMap::new();
        users.insert("admin".to_string(), "secret123".to_string());
        let auth = ApplicationAuth::password(users);

        let credentials = BASE64_STANDARD.encode("admin:secret123");
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("http://example.com:443")
            .header("Proxy-Authorization", format!("Basic {}", credentials))
            .body(())
            .unwrap();
        assert!(auth.verify(&req).is_ok());
    }

    #[test]
    fn test_application_auth_password_invalid_credentials() {
        let mut users = std::collections::HashMap::new();
        users.insert("admin".to_string(), "secret123".to_string());
        let auth = ApplicationAuth::password(users);

        let credentials = BASE64_STANDARD.encode("admin:wrongpassword");
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("http://example.com:443")
            .header("Proxy-Authorization", format!("Basic {}", credentials))
            .body(())
            .unwrap();
        assert!(auth.verify(&req).is_err());
    }

    #[test]
    fn test_application_auth_password_missing_header() {
        let mut users = std::collections::HashMap::new();
        users.insert("admin".to_string(), "secret123".to_string());
        let auth = ApplicationAuth::password(users);

        let req = http::Request::builder()
            .method("CONNECT")
            .uri("http://example.com:443")
            .body(())
            .unwrap();
        assert!(auth.verify(&req).is_err());
    }

    #[test]
    fn test_application_auth_from_config_no_password() {
        let config = crate::auth::MultiAuthConfig::default();
        let auth = ApplicationAuth::from_config(&config);
        assert!(!auth.is_required());
    }

    #[test]
    fn test_application_auth_from_config_with_password() {
        use crate::auth::config::{AuthConfig, AuthType, UserCredential};

        let config = crate::auth::MultiAuthConfig {
            configs: vec![AuthConfig {
                auth_type: AuthType::Password,
                users: Some(vec![UserCredential {
                    username: "admin".to_string(),
                    password: "secret123".to_string(),
                }]),
                client_ca_path: None,
            }],
        };
        let auth = ApplicationAuth::from_config(&config);
        assert!(
            auth.is_required(),
            "from_config with password config must produce required auth"
        );

        // Verify that the auth can actually verify credentials
        let credentials = BASE64_STANDARD.encode("admin:secret123");
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("http://example.com:443")
            .header("Proxy-Authorization", format!("Basic {}", credentials))
            .body(())
            .unwrap();
        assert!(
            auth.verify(&req).is_ok(),
            "auth from_config should verify correct credentials"
        );
    }
}
