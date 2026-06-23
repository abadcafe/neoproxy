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
use rustls::InconsistentKeys;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{
  ClientHello, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::{CertifiedKey, SigningKey};
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
/// There is no default certificate - unknown SNI results in handshake
/// failure.
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
/// - "*.example.com" does NOT match multi-level subdomain:
///   "bar.foo.example.com"
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

  // Empty prefix means hostname == ".example.com" (with leading dot) -
  // weird but allow
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
  let signing_key = load_signing_key(key.clone_key())
    .map_err(|e| anyhow!("Unsupported private key type: {:?}", e))?;

  // Create a CertifiedKey and verify the keys match
  let certified_key = CertifiedKey::new(certs.clone(), signing_key);

  // Use rustls's built-in key consistency check
  match certified_key.keys_match() {
    Ok(()) => {
      // Keys match, all good
    }
    Err(rustls::Error::InconsistentKeys(
      InconsistentKeys::KeyMismatch,
    )) => {
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

/// Load a signing key using the default crypto provider.
/// Provider-agnostic: works with both ring and rustls-openssl.
pub fn load_signing_key(
  key: PrivateKeyDer<'static>,
) -> Result<Arc<dyn SigningKey>> {
  let provider = rustls::crypto::CryptoProvider::get_default()
    .expect("CryptoProvider must be installed before loading keys");
  Ok(provider.key_provider.load_private_key(key)?)
}

/// Extract Subject Alternative Names (SAN) from a certificate.
///
/// SAN entries typically contain DNS names that the certificate is
/// valid for. These are used to build the SNI-to-certificate mapping.
///
/// Note: This function uses a simple approach - it parses the
/// certificate using x509-parser to extract SAN entries. For
/// production, consider caching the parsed certificates.
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
/// No default certificate is used - unknown SNI will cause TLS
/// handshake failure.
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
        load_signing_key(key.clone_key()).map_err(|e| {
          anyhow!("Unsupported private key type: {:?}", e)
        })?,
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
            // Continue anyway - the certificate might still work for
            // some clients
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
/// - Requests client certificates but does not require them
///   (allow_unauthenticated). The actual enforcement happens at the
///   HTTP layer after routing to the correct server.
///
/// Note: This takes the full routing table to support multi-server
/// certificate selection. Client CA certificates from all servers
/// are merged into a single verifier.
pub fn build_tls_server_config(
  servers: &[Server],
  alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
  let sni_resolver = build_sni_resolver(servers)?;

  // Collect all client_ca_certs from all servers
  let mut roots = rustls::RootCertStore::empty();
  let mut has_client_ca = false;

  for server in servers {
    if let Some(tls) = &server.tls {
      if let Some(client_ca_certs) = &tls.client_ca_certs {
        has_client_ca = true;
        for ca_path in client_ca_certs {
          let ca_file = File::open(ca_path).with_context(|| {
            format!("Failed to open client CA file: {}", ca_path)
          })?;
          let mut ca_reader = BufReader::new(ca_file);
          let ca_certs: Vec<CertificateDer> =
            rustls_pemfile::certs(&mut ca_reader)
              .collect::<Result<Vec<_>, _>>()
              .with_context(|| {
                "Failed to parse client CA certificates"
              })?;
          for cert in ca_certs {
            roots.add(cert)?;
          }
        }
      }
    }
  }

  let mut config = if has_client_ca {
    // Request client certificates but allow unauthenticated
    // connections. Per-server enforcement happens at the HTTP layer
    // after routing.
    let verifier = WebPkiClientVerifier::builder(roots.into())
      .allow_unauthenticated()
      .build()?;
    rustls::ServerConfig::builder()
      .with_client_cert_verifier(verifier)
      .with_cert_resolver(sni_resolver)
  } else {
    rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(sni_resolver)
  };

  config.alpn_protocols = alpn_protocols;

  Ok(Arc::new(config))
}
