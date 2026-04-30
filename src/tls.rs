//! TLS utilities for certificate loading and SNI routing.
//!
//! This module provides:
//! - Certificate loading from PEM files
//! - SAN (Subject Alternative Name) extraction
//! - SNI-to-certificate mapping with wildcard support

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{
  ClientHello, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

use crate::config::CertificateConfig;
use crate::server::Server;

/// SNI resolver that supports exact and wildcard domain matching.
///
/// This resolver:
/// 1. First attempts exact domain match
/// 2. Then tries wildcard patterns in configuration order
/// 3. Returns None if no match (TLS handshake will fail)
///
/// There is no default certificate - unknown SNI results in handshake failure.
#[derive(Debug)]
pub struct SniResolver {
  /// Exact domain -> certificate mapping
  exact_certs: HashMap<String, Arc<CertifiedKey>>,
  /// Wildcard patterns -> certificate (ordered by configuration)
  wildcard_certs: Vec<(String, Arc<CertifiedKey>)>,
}

impl SniResolver {
  /// Create a new empty resolver.
  pub fn new() -> Self {
    Self { exact_certs: HashMap::new(), wildcard_certs: Vec::new() }
  }

  /// Add an exact domain mapping.
  pub fn add_exact(&mut self, domain: String, cert: Arc<CertifiedKey>) {
    self.exact_certs.insert(domain, cert);
  }

  /// Add a wildcard domain mapping.
  pub fn add_wildcard(
    &mut self,
    pattern: String,
    cert: Arc<CertifiedKey>,
  ) {
    self.wildcard_certs.push((pattern, cert));
  }
}

impl Default for SniResolver {
  fn default() -> Self {
    Self::new()
  }
}

impl ResolvesServerCert for SniResolver {
  fn resolve(
    &self,
    client_hello: ClientHello<'_>,
  ) -> Option<Arc<CertifiedKey>> {
    let sni = client_hello.server_name()?;

    // 1. Exact match
    if let Some(cert) = self.exact_certs.get(sni) {
      return Some(cert.clone());
    }

    // 2. Wildcard match (in configuration order)
    for (pattern, cert) in &self.wildcard_certs {
      if matches_wildcard(pattern, sni) {
        return Some(cert.clone());
      }
    }

    // 3. No match - return None, TLS handshake will fail
    None
  }
}

/// Check if a hostname matches a wildcard pattern.
///
/// Rules:
/// - Pattern must start with "*."
/// - "*.example.com" matches single-level subdomain: "foo.example.com"
/// - "*.example.com" matches bare domain: "example.com"
/// - "*.example.com" does NOT match multi-level subdomain: "bar.foo.example.com"
fn matches_wildcard(pattern: &str, hostname: &str) -> bool {
  if !pattern.starts_with("*.") {
    return false;
  }

  let suffix = &pattern[1..]; // ".example.com"

  // Check bare domain match: hostname == "example.com"
  if hostname == &pattern[2..] {
    return true;
  }

  // Check subdomain match: hostname ends with ".example.com"
  if !hostname.ends_with(suffix) {
    return false;
  }

  // Get the prefix (subdomain part)
  let prefix_len = hostname.len() - suffix.len();
  let prefix = &hostname[..prefix_len];

  // Empty prefix means hostname == ".example.com" (with leading dot) - weird but allow
  if prefix.is_empty() {
    return true;
  }

  // Prefix should not contain "." (single-level subdomain only)
  // "foo" is ok, "bar.foo" is not
  !prefix.contains('.')
}

/// Load certificates and private key from a certificate config.
///
/// Returns a tuple of (certificates, private_key).
///
/// This function also validates that the certificate and key match,
/// catching configuration errors at startup time.
pub fn load_cert_and_key(
  config: &CertificateConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
  // Load certificate file
  let cert_file = File::open(&config.cert_path).with_context(|| {
    format!("Failed to open certificate file: {}", config.cert_path)
  })?;
  let mut cert_reader = BufReader::new(cert_file);
  let certs: Vec<CertificateDer> =
    rustls_pemfile::certs(&mut cert_reader)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| "Failed to parse certificates")?;

  if certs.is_empty() {
    bail!("No certificates found in {}", config.cert_path);
  }

  // Load private key
  let key_file = File::open(&config.key_path).with_context(|| {
    format!("Failed to open private key file: {}", config.key_path)
  })?;
  let mut key_reader = BufReader::new(key_file);
  let key =
    rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
      anyhow!("No private key found in {}", config.key_path)
    })?;

  // Create signing key to verify it's valid
  let signing_key =
    rustls::crypto::ring::sign::any_supported_type(&key)
      .map_err(|e| anyhow!("Unsupported private key type: {:?}", e))?;

  // Create a CertifiedKey and verify the keys match
  let certified_key = CertifiedKey::new(certs.clone(), signing_key);

  // Use rustls's built-in key consistency check
  match certified_key.keys_match() {
    Ok(()) => {
      // Keys match, all good
    }
    Err(rustls::Error::InconsistentKeys(_)) => {
      bail!(
        "Certificate and private key do not match: {} and {}",
        config.cert_path,
        config.key_path
      );
    }
    Err(rustls::Error::NoCertificatesPresented) => {
      bail!("No certificates provided");
    }
    Err(e) => {
      // Unknown consistency - this is OK, continue
      // rustls will validate during handshake
      warn!("Could not verify certificate/key consistency: {}", e);
    }
  }

  Ok((certs, key))
}

/// Extract Subject Alternative Names (SAN) from a certificate.
///
/// SAN entries typically contain DNS names that the certificate is valid for.
/// These are used to build the SNI-to-certificate mapping.
///
/// Note: This function uses a simple approach - it parses the certificate
/// using x509-parser to extract SAN entries. For production, consider
/// caching the parsed certificates.
pub fn extract_san_dns_names(
  cert: &CertificateDer,
) -> Result<Vec<String>> {
  // Use x509-parser to extract SAN
  let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
    .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

  let mut dns_names = Vec::new();

  // Extract SAN extension
  if let Some(san_ext) = parsed.extensions().iter().find(|ext| {
    ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME
  }) {
    if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for entry in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(name) = entry {
                    dns_names.push(name.to_string());
                }
            }
        }
  }

  Ok(dns_names)
}

/// Build an SNI resolver from multiple servers' TLS configurations.
///
/// This function:
/// 1. Iterates through all servers in the routing table
/// 2. Loads certificates from each server's TLS config
/// 3. Extracts SAN from each certificate
/// 4. Builds exact and wildcard SNI mappings
///
/// No default certificate is used - unknown SNI will cause TLS handshake failure.
pub fn build_sni_resolver(
  servers: &[Server],
) -> Result<Arc<SniResolver>> {
  let mut resolver = SniResolver::new();

  for server in servers {
    let Some(tls) = &server.tls else {
      continue;
    };

    if tls.certificates.is_empty() {
      warn!(
        "Server '{}' has TLS config but no certificates",
        server.service_name
      );
      continue;
    }

    for cert_config in &tls.certificates {
      let (certs, key) = load_cert_and_key(cert_config)?;

      // Build certified key
      let certified_key = CertifiedKey::new(
        certs.clone(),
        rustls::crypto::ring::sign::any_supported_type(&key).map_err(
          |e| anyhow!("Unsupported private key type: {:?}", e),
        )?,
      );
      let certified_key = Arc::new(certified_key);

      // Extract SAN and add to resolver
      for cert_der in &certs {
        match extract_san_dns_names(cert_der) {
          Ok(dns_names) => {
            for name in dns_names {
              if name.starts_with("*.") {
                info!(
                  "Adding wildcard SNI mapping: {} -> {}",
                  name, cert_config.cert_path
                );
                resolver.add_wildcard(name, certified_key.clone());
              } else {
                info!(
                  "Adding exact SNI mapping: {} -> {}",
                  name, cert_config.cert_path
                );
                resolver.add_exact(name, certified_key.clone());
              }
            }
          }
          Err(e) => {
            warn!("Failed to extract SAN from certificate: {}", e);
            // Continue anyway - the certificate might still work for some clients
          }
        }
      }
    }
  }

  Ok(Arc::new(resolver))
}

/// Build TLS server config with SNI support.
///
/// Creates a rustls::ServerConfig that:
/// - Uses SNI resolver for certificate selection
/// - Optionally requires client certificates for mTLS
///
/// Note: This takes the full routing table to support multi-server certificate selection.
pub fn build_tls_server_config(
  servers: &[Server],
  alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
  let sni_resolver = build_sni_resolver(servers)?;

  // Build client cert verifier if configured
  // Use the first server's client_ca_certs for mTLS
  let client_verifier = servers
    .iter()
    .find_map(|s| s.tls.as_ref())
    .and_then(|tls| tls.client_ca_certs.as_ref())
    .map(|client_ca_certs| -> Result<_> {
      let mut roots = rustls::RootCertStore::empty();
      for ca_path in client_ca_certs {
        let ca_file = File::open(ca_path).with_context(|| {
          format!("Failed to open client CA file: {}", ca_path)
        })?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer> =
          rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .with_context(
              || "Failed to parse client CA certificates",
            )?;
        for cert in ca_certs {
          roots.add(cert)?;
        }
      }
      Ok(WebPkiClientVerifier::builder(roots.into()).build()?)
    })
    .transpose()?;

  let mut config = match client_verifier {
    Some(verifier) => rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_cert_resolver(sni_resolver),
    None => rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(sni_resolver),
  };

  config.alpn_protocols = alpn_protocols;

  Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::OnceLock;

  static CRYPTO_PROVIDER_INSTALLED: OnceLock<bool> = OnceLock::new();

  /// Ensure the rustls crypto provider is installed for tests.
  fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
      let _ =
        rustls::crypto::ring::default_provider().install_default();
      true
    });
  }

  /// Generate a test certificate with specified SAN entries.
  fn generate_test_cert_with_san(
    san_entries: Vec<String>,
  ) -> (String, String, tempfile::TempDir) {
    ensure_crypto_provider();
    let temp_dir = tempfile::tempdir().unwrap();

    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params =
      rcgen::CertificateParams::new(san_entries.clone()).unwrap();
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages =
      vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
      .distinguished_name
      .push(rcgen::DnType::CommonName, "test.local");

    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_path = temp_dir.path().join("test_cert.pem");
    let key_path = temp_dir.path().join("test_key.pem");

    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    (
      cert_path.to_str().unwrap().to_string(),
      key_path.to_str().unwrap().to_string(),
      temp_dir,
    )
  }

  #[test]
  fn test_extract_san_from_certificate() {
    ensure_crypto_provider();

    // Create a test certificate with known SAN entries
    let (cert_path, _key_path, _temp_dir) =
      generate_test_cert_with_san(vec![
        "test.example.com".to_string(),
        "api.example.com".to_string(),
      ]);

    // Load the certificate
    let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
    let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(
      cert_pem.as_bytes(),
    ))
    .next()
    .unwrap()
    .unwrap();

    // Extract SAN
    let san_names = extract_san_dns_names(&cert_der).unwrap();

    assert!(san_names.contains(&"test.example.com".to_string()));
    assert!(san_names.contains(&"api.example.com".to_string()));
  }

  #[test]
  fn test_extract_san_empty_cert() {
    ensure_crypto_provider();

    // An empty certificate der should fail to parse
    let empty_cert = CertificateDer::from(vec![]);
    let result = extract_san_dns_names(&empty_cert);
    assert!(result.is_err());
  }

  #[test]
  fn test_load_cert_and_key_missing_file() {
    ensure_crypto_provider();

    let config = CertificateConfig {
      cert_path: "/nonexistent/path/cert.pem".to_string(),
      key_path: "/nonexistent/path/key.pem".to_string(),
    };
    let result = load_cert_and_key(&config);
    assert!(result.is_err());
  }

  #[test]
  fn test_matches_wildcard_exact_subdomain() {
    // "*.example.com" matches "foo.example.com"
    assert!(matches_wildcard("*.example.com", "foo.example.com"));
    assert!(matches_wildcard("*.example.com", "api.example.com"));
  }

  #[test]
  fn test_matches_wildcard_bare_domain() {
    // "*.example.com" matches "example.com" (bare domain)
    assert!(matches_wildcard("*.example.com", "example.com"));
  }

  #[test]
  fn test_matches_wildcard_too_deep() {
    // "*.example.com" does NOT match "bar.foo.example.com"
    assert!(!matches_wildcard("*.example.com", "bar.foo.example.com"));
    assert!(!matches_wildcard("*.example.com", "a.b.example.com"));
  }

  #[test]
  fn test_matches_wildcard_different_domain() {
    // "*.example.com" does not match "foo.other.com"
    assert!(!matches_wildcard("*.example.com", "foo.other.com"));
    assert!(!matches_wildcard("*.example.com", "example.org"));
  }

  #[test]
  fn test_matches_wildcard_non_wildcard_pattern() {
    // Non-wildcard patterns return false
    assert!(!matches_wildcard("example.com", "example.com"));
    assert!(!matches_wildcard("foo.example.com", "foo.example.com"));
  }

  #[test]
  fn test_sni_resolver_exact_match() {
    ensure_crypto_provider();

    let (cert_path, key_path, _temp_dir) =
      generate_test_cert_with_san(vec!["test.example.com".to_string()]);

    let config = CertificateConfig { cert_path, key_path };
    let (certs, key) = load_cert_and_key(&config).unwrap();
    let certified_key = Arc::new(CertifiedKey::new(
      certs,
      rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
    ));

    let mut resolver = SniResolver::new();
    resolver.add_exact("test.example.com".to_string(), certified_key);

    // Should resolve exact match
    // Note: We can't easily test resolve() without mocking ClientHello
    assert!(resolver.exact_certs.contains_key("test.example.com"));
  }

  #[test]
  fn test_sni_resolver_wildcard_match() {
    ensure_crypto_provider();

    let (cert_path, key_path, _temp_dir) =
      generate_test_cert_with_san(vec!["*.example.com".to_string()]);

    let config = CertificateConfig { cert_path, key_path };
    let (certs, key) = load_cert_and_key(&config).unwrap();
    let certified_key = Arc::new(CertifiedKey::new(
      certs,
      rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
    ));

    let mut resolver = SniResolver::new();
    resolver.add_wildcard("*.example.com".to_string(), certified_key);

    assert_eq!(resolver.wildcard_certs.len(), 1);
    assert_eq!(resolver.wildcard_certs[0].0, "*.example.com");
  }

  #[test]
  fn test_sni_resolver_no_match_returns_none() {
    ensure_crypto_provider();

    let (cert_path, key_path, _temp_dir) =
      generate_test_cert_with_san(vec!["test.example.com".to_string()]);

    let config = CertificateConfig { cert_path, key_path };
    let (certs, key) = load_cert_and_key(&config).unwrap();
    let certified_key = Arc::new(CertifiedKey::new(
      certs,
      rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
    ));

    let mut resolver = SniResolver::new();
    resolver.add_exact("test.example.com".to_string(), certified_key);

    // No default certificate - should only match exact
    assert!(resolver.exact_certs.contains_key("test.example.com"));
    assert!(!resolver.exact_certs.contains_key("other.example.com"));
  }

  #[test]
  fn test_build_tls_server_config_with_multiple_servers() {
    ensure_crypto_provider();

    // Create two test certificates with different SAN entries
    let (cert_path1, key_path1, _temp_dir1) =
      generate_test_cert_with_san(vec!["app1.example.com".to_string()]);
    let (cert_path2, key_path2, _temp_dir2) =
      generate_test_cert_with_san(vec!["app2.example.com".to_string()]);

    let servers = vec![
      Server {
        hostnames: vec!["app1.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "server1".to_string(),
        users: None,
        tls: Some(crate::config::ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: cert_path1,
            key_path: key_path1,
          }],
          client_ca_certs: None,
        }),
        access_log_writer: None,
      },
      Server {
        hostnames: vec!["app2.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "server2".to_string(),
        users: None,
        tls: Some(crate::config::ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: cert_path2,
            key_path: key_path2,
          }],
          client_ca_certs: None,
        }),
        access_log_writer: None,
      },
    ];

    // Build TLS config
    let result =
      build_tls_server_config(&servers, vec![b"http/1.1".to_vec()]);
    assert!(result.is_ok());

    let config = result.unwrap();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
  }

  #[test]
  fn test_build_tls_server_config_no_certificates() {
    ensure_crypto_provider();

    // Empty servers list
    let servers: Vec<Server> = vec![];

    let result =
      build_tls_server_config(&servers, vec![b"http/1.1".to_vec()]);
    // Should succeed but resolver will have no certificates
    assert!(result.is_ok());
  }
}
