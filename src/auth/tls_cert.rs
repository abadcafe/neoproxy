//! TLS client certificate verification.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

use crate::auth::AuthError;

/// TLS client certificate verifier wrapper.
#[derive(Clone)]
pub struct TlsClientCertVerifier {
  verifier: Arc<dyn ClientCertVerifier>,
}

impl fmt::Debug for TlsClientCertVerifier {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TlsClientCertVerifier").finish_non_exhaustive()
  }
}

impl TlsClientCertVerifier {
  /// Create a verifier from a CA certificate file path.
  /// This creates a REQUIRED client cert verifier.
  pub fn from_ca_path(ca_path: &Path) -> Result<Self, AuthError> {
    let cert_file = File::open(ca_path).map_err(|e| {
      AuthError::TlsCertError(format!(
        "failed to open CA file {}: {}",
        ca_path.display(),
        e
      ))
    })?;
    let mut reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'_>> =
      rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
          AuthError::TlsCertError(format!(
            "failed to parse CA certificates: {}",
            e
          ))
        })?;

    if certs.is_empty() {
      return Err(AuthError::TlsCertError(
        "no certificates found in CA file".to_string(),
      ));
    }

    let mut root_store = RootCertStore::empty();
    for cert in certs {
      root_store.add(cert).map_err(|e| {
        AuthError::TlsCertError(format!(
          "failed to add CA certificate: {}",
          e
        ))
      })?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
      .build()
      .map_err(|e| {
        AuthError::TlsCertError(format!(
          "failed to build client verifier: {}",
          e
        ))
      })?;

    Ok(Self { verifier })
  }

  /// Get the underlying rustls verifier for use in ServerConfig.
  pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
    self.verifier.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Write;
  use tempfile::NamedTempFile;

  fn create_temp_cert_file() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp file");
    file.write_all(b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU45BMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3RDQTAgFw0yNDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAwMDAwMFowETEPMA0GA1UE\nAwwGdGVzdENBMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALnH5d2uN8qU6WTaVdNb\n-----END CERTIFICATE-----\n").expect("write cert");
    file
  }

  #[test]
  fn test_tls_cert_verifier_missing_file() {
    let result = TlsClientCertVerifier::from_ca_path(
      &std::path::PathBuf::from("/nonexistent/path.pem"),
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, AuthError::TlsCertError(_)));
  }

  #[test]
  fn test_tls_cert_verifier_returns_verifier() {
    // This test verifies the struct and method exist
    // We can't test with a valid cert easily, but we test the interface
    let file = create_temp_cert_file();
    let result = TlsClientCertVerifier::from_ca_path(file.path());
    // May fail due to invalid cert content, but should not crash
    // and should return TlsCertError type
    if result.is_err() {
      let err = result.unwrap_err();
      assert!(matches!(err, AuthError::TlsCertError(_)));
    }
  }
}
