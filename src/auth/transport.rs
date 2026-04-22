//! Transport layer authentication (TLS client certificate).
//!
//! This module handles TLS-level authentication independently from
//! application-level authentication. When configured, TLS client cert
//! verification is REQUIRED - failure means connection rejection.

use std::sync::Arc;

use crate::auth::tls_cert::TlsClientCertVerifier;
use crate::auth::config::MultiAuthConfig;
use crate::auth::AuthError;

/// Transport layer authenticator.
///
/// Handles TLS client certificate verification at the transport level.
/// When a verifier is configured, client certificates are REQUIRED.
/// This is independent of application-layer authentication.
#[derive(Clone)]
pub struct TransportAuth {
    verifier: Option<TlsClientCertVerifier>,
}

impl TransportAuth {
    /// Create a TransportAuth with no verification (no TLS client cert required).
    pub fn none() -> Self {
        Self { verifier: None }
    }

    /// Create a TransportAuth with a TLS client cert verifier.
    pub fn with_verifier(verifier: TlsClientCertVerifier) -> Self {
        Self { verifier: Some(verifier) }
    }

    /// Build from MultiAuthConfig, loading the TLS verifier from disk.
    ///
    /// Returns Err if the config specifies tls_client_cert but the CA file
    /// cannot be loaded.
    pub fn from_config_load(config: &MultiAuthConfig) -> Result<Self, AuthError> {
        if config.has_tls_client_cert() {
            let ca_path = config.client_ca_pathbuf().ok_or_else(|| {
                AuthError::ConfigError(
                    "client_ca_path required for tls_client_cert auth".to_string(),
                )
            })?;
            let verifier = TlsClientCertVerifier::from_ca_path(&ca_path)?;
            Ok(Self::with_verifier(verifier))
        } else {
            Ok(Self::none())
        }
    }

    /// Whether transport-layer authentication is required.
    #[allow(dead_code)]
    pub fn is_required(&self) -> bool {
        self.verifier.is_some()
    }

    /// Get the underlying rustls verifier for use in TLS ServerConfig.
    ///
    /// Returns `Some(verifier)` when TLS client cert auth is configured,
    /// `None` otherwise. The verifier enforces REQUIRED client certs.
    pub fn rustls_verifier(&self) -> Option<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
        self.verifier.as_ref().map(|v| v.verifier())
    }
}

impl std::fmt::Debug for TransportAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportAuth")
            .field("is_required", &self.is_required())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Ensure rustls crypto provider is installed for tests.
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// Generate a self-signed CA certificate in temp_dir using openssl CLI.
    /// Returns the path to the CA cert PEM file.
    fn generate_test_ca(temp_dir: &TempDir) -> std::path::PathBuf {
        let ca_key_path = temp_dir.path().join("ca.key");
        let ca_cert_path = temp_dir.path().join("ca.crt");

        let output = std::process::Command::new("openssl")
            .args([
                "req", "-new", "-x509", "-nodes",
                "-keyout", ca_key_path.to_str().unwrap(),
                "-out", ca_cert_path.to_str().unwrap(),
                "-days", "1",
                "-subj", "/CN=TestCA",
            ])
            .output()
            .expect("openssl command failed");
        assert!(output.status.success(), "openssl failed: {}", String::from_utf8_lossy(&output.stderr));

        ca_cert_path
    }

    #[test]
    fn test_transport_auth_none_is_not_required() {
        let auth = TransportAuth::none();
        assert!(!auth.is_required());
    }

    #[test]
    fn test_transport_auth_none_has_no_rustls_verifier() {
        let auth = TransportAuth::none();
        assert!(auth.rustls_verifier().is_none(),
            "TransportAuth::none() should not produce a rustls verifier");
    }

    #[test]
    fn test_transport_auth_with_verifier_is_required() {
        ensure_crypto_provider();
        let temp_dir = TempDir::new().unwrap();
        let ca_path = generate_test_ca(&temp_dir);
        let verifier = crate::auth::tls_cert::TlsClientCertVerifier::from_ca_path(&ca_path)
            .expect("should load CA");
        let auth = TransportAuth::with_verifier(verifier);
        assert!(auth.is_required(),
            "TransportAuth::with_verifier() must be required");
    }

    #[test]
    fn test_transport_auth_with_verifier_has_rustls_verifier() {
        ensure_crypto_provider();
        let temp_dir = TempDir::new().unwrap();
        let ca_path = generate_test_ca(&temp_dir);
        let verifier = crate::auth::tls_cert::TlsClientCertVerifier::from_ca_path(&ca_path)
            .expect("should load CA");
        let auth = TransportAuth::with_verifier(verifier);
        assert!(auth.rustls_verifier().is_some(),
            "TransportAuth::with_verifier() must produce a rustls verifier");
    }

    #[test]
    fn test_transport_auth_from_config_load_no_tls() {
        let config = crate::auth::MultiAuthConfig::default();
        let auth = TransportAuth::from_config_load(&config)
            .expect("should succeed for empty config");
        assert!(!auth.is_required());
    }

    #[test]
    fn test_transport_auth_from_config_load_with_tls() {
        ensure_crypto_provider();
        let temp_dir = TempDir::new().unwrap();
        let ca_path = generate_test_ca(&temp_dir);
        let config = crate::auth::MultiAuthConfig {
            configs: vec![crate::auth::config::AuthConfig {
                auth_type: crate::auth::config::AuthType::TlsClientCert,
                users: None,
                client_ca_path: Some(ca_path.to_str().unwrap().to_string()),
            }],
        };
        let auth = TransportAuth::from_config_load(&config)
            .expect("should load verifier from config");
        assert!(auth.is_required(),
            "from_config_load with tls_client_cert config must produce required auth");
    }
}
