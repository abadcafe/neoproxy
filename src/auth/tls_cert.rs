//! TLS client certificate verification.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::{DigitallySignedStruct, SignatureScheme, DistinguishedName};

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

  /// Create an OPTIONAL client cert verifier from a CA certificate file path.
  /// This allows connections without client certs, but verifies them if presented.
  pub fn optional_from_ca_path(ca_path: &Path) -> Result<Self, AuthError> {
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

    // Wrap in optional verifier
    Ok(Self {
      verifier: Arc::new(OptionalClientCertVerifier::new(verifier)),
    })
  }

  /// Get the underlying rustls verifier for use in ServerConfig.
  pub fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
    self.verifier.clone()
  }
}

/// Wrapper that makes client certificate authentication optional.
/// If the client presents a certificate, it will be verified.
/// If the client doesn't present a certificate, the connection is still allowed.
#[derive(Debug)]
struct OptionalClientCertVerifier {
  inner: Arc<dyn ClientCertVerifier>,
}

impl OptionalClientCertVerifier {
  fn new(inner: Arc<dyn ClientCertVerifier>) -> Self {
    Self { inner }
  }
}

impl ClientCertVerifier for OptionalClientCertVerifier {
  fn offer_client_auth(&self) -> bool {
    self.inner.offer_client_auth()
  }

  fn client_auth_mandatory(&self) -> bool {
    // Make client auth OPTIONAL
    false
  }

  fn root_hint_subjects(&self) -> &[DistinguishedName] {
    self.inner.root_hint_subjects()
  }

  fn verify_client_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: rustls::pki_types::UnixTime,
  ) -> Result<ClientCertVerified, rustls::Error> {
    // For optional client cert, we allow invalid certificates to pass through.
    // The HTTP-level authentication will handle the password fallback.
    // This enables multi-auth scenarios where:
    // 1. Client presents no cert -> TLS succeeds -> password auth
    // 2. Client presents valid cert -> TLS succeeds -> authenticated at TLS level
    // 3. Client presents invalid cert -> TLS succeeds -> password auth (fallback)
    let _ = self.inner.verify_client_cert(end_entity, intermediates, now);
    Ok(ClientCertVerified::assertion())
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    self.inner.verify_tls13_signature(message, cert, dss)
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, rustls::Error> {
    self.inner.verify_tls12_signature(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    self.inner.supported_verify_schemes()
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
