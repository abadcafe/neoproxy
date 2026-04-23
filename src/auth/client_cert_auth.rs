//! Client certificate authentication (TLS layer).
//!
//! Handles TLS client certificate verification at the transport level.
//! When a verifier is configured, client certificates are REQUIRED.

use std::sync::Arc;

use crate::auth::AuthError;
use crate::auth::listener_auth_config::ListenerAuthConfig;
use crate::auth::tls_cert::TlsClientCertVerifier;

/// Client certificate authenticator (TLS layer).
///
/// Handles TLS client certificate verification. When a verifier is configured,
/// client certificates are REQUIRED — failure means connection rejection.
/// This is independent of application-layer (password) authentication.
#[derive(Clone)]
pub struct ClientCertAuth {
  verifier: Option<TlsClientCertVerifier>,
}

impl ClientCertAuth {
  /// Create a ClientCertAuth with no verification (no TLS client cert required).
  pub fn none() -> Self {
    Self { verifier: None }
  }

  /// Build from ListenerAuthConfig, loading the TLS verifier from disk if
  /// `client_ca_path` is present.
  ///
  /// Returns Err if the CA file cannot be loaded.
  pub fn from_config(
    config: &ListenerAuthConfig,
  ) -> Result<Self, AuthError> {
    match config.client_ca_pathbuf() {
      Some(ca_path) => {
        let verifier = TlsClientCertVerifier::from_ca_path(&ca_path)?;
        Ok(Self { verifier: Some(verifier) })
      }
      None => Ok(Self::none()),
    }
  }

  /// Get the underlying rustls verifier for use in TLS ServerConfig.
  ///
  /// Returns `Some(verifier)` when TLS client cert auth is configured,
  /// `None` otherwise.
  pub fn rustls_verifier(
    &self,
  ) -> Option<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    self.verifier.as_ref().map(|v| v.verifier())
  }
}

impl std::fmt::Debug for ClientCertAuth {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ClientCertAuth")
      .field("has_verifier", &self.verifier.is_some())
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use tempfile::TempDir;

  fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
  }

  fn generate_test_ca(temp_dir: &TempDir) -> std::path::PathBuf {
    let ca_key_path = temp_dir.path().join("ca.key");
    let ca_cert_path = temp_dir.path().join("ca.crt");
    let output = std::process::Command::new("openssl")
      .args([
        "req",
        "-new",
        "-x509",
        "-nodes",
        "-keyout",
        ca_key_path.to_str().unwrap(),
        "-out",
        ca_cert_path.to_str().unwrap(),
        "-days",
        "1",
        "-subj",
        "/CN=TestCA",
      ])
      .output()
      .expect("openssl command failed");
    assert!(
      output.status.success(),
      "openssl failed: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    ca_cert_path
  }

  #[test]
  fn test_client_cert_auth_none_has_no_verifier() {
    let auth = ClientCertAuth::none();
    assert!(auth.rustls_verifier().is_none());
  }

  #[test]
  fn test_client_cert_auth_from_config_no_ca() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: Some(vec![
          crate::auth::listener_auth_config::UserCredential {
            username: "admin".to_string(),
            password: "secret".to_string(),
          },
        ]),
        client_ca_path: None,
      };
    let auth =
      ClientCertAuth::from_config(&config).expect("should succeed");
    assert!(
      auth.rustls_verifier().is_none(),
      "No client_ca_path means no verifier"
    );
  }

  #[test]
  fn test_client_cert_auth_from_config_with_ca() {
    ensure_crypto_provider();
    let temp_dir = TempDir::new().unwrap();
    let ca_path = generate_test_ca(&temp_dir);
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: None,
        client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
      };
    let auth =
      ClientCertAuth::from_config(&config).expect("should load CA");
    assert!(
      auth.rustls_verifier().is_some(),
      "With client_ca_path, verifier should be present"
    );
  }

  #[test]
  fn test_client_cert_auth_from_config_invalid_ca_path() {
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: None,
        client_ca_path: Some("/nonexistent/ca.pem".to_string()),
      };
    let result = ClientCertAuth::from_config(&config);
    assert!(result.is_err(), "Invalid CA path should fail");
  }

  #[test]
  fn test_client_cert_auth_debug_no_verifier() {
    let auth = ClientCertAuth::none();
    let debug_str = format!("{:?}", auth);
    assert!(
      debug_str.contains("false"),
      "Debug should show verifier is_some=false"
    );
  }

  #[test]
  fn test_client_cert_auth_debug_with_verifier() {
    ensure_crypto_provider();
    let temp_dir = TempDir::new().unwrap();
    let ca_path = generate_test_ca(&temp_dir);
    let config =
      crate::auth::listener_auth_config::ListenerAuthConfig {
        users: None,
        client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
      };
    let auth =
      ClientCertAuth::from_config(&config).expect("should load CA");
    let debug_str = format!("{:?}", auth);
    assert!(
      debug_str.contains("true"),
      "Debug should show verifier is_some=true"
    );
  }
}
