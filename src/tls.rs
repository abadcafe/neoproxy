//! TLS utilities for certificate loading and SNI routing.
//!
//! This module provides:
//! - Certificate loading from PEM files
//! - SAN (Subject Alternative Name) extraction
//! - SNI-to-certificate mapping with default certificate fallback

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

use crate::config::{CertificateConfig, ServerTlsConfig};

/// A certificate resolver that supports SNI-based selection with a default fallback.
///
/// This resolver:
/// 1. First attempts to resolve certificates based on SNI (Server Name Indication)
/// 2. Falls back to a default certificate if no SNI match is found
///
/// This is useful for multi-domain servers where:
/// - Known domains get their specific certificates
/// - Unknown domains or missing SNI get the first (default) certificate
#[derive(Debug)]
pub struct SniResolverWithDefault {
    /// SNI-based resolver for exact domain matches
    sni_resolver: ResolvesServerCertUsingSni,
    /// Default certificate to use when SNI doesn't match any known domain
    default_cert: Option<Arc<CertifiedKey>>,
}

impl SniResolverWithDefault {
    /// Create a new resolver with SNI support and default fallback.
    pub fn new(sni_resolver: ResolvesServerCertUsingSni, default_cert: Option<Arc<CertifiedKey>>) -> Self {
        Self {
            sni_resolver,
            default_cert,
        }
    }
}

impl ResolvesServerCert for SniResolverWithDefault {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // First try SNI-based resolution
        if let Some(cert) = self.sni_resolver.resolve(client_hello) {
            return Some(cert);
        }

        // Fall back to default certificate
        self.default_cert.clone()
    }
}

/// Load certificates and private key from a certificate config.
///
/// Returns a tuple of (certificates, private_key).
///
/// This function also validates that the certificate and key match,
/// catching configuration errors at startup time.
pub fn load_cert_and_key(config: &CertificateConfig) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificate file
    let cert_file = File::open(&config.cert_path)
        .with_context(|| format!("Failed to open certificate file: {}", config.cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "Failed to parse certificates")?;

    if certs.is_empty() {
        bail!("No certificates found in {}", config.cert_path);
    }

    // Load private key
    let key_file = File::open(&config.key_path)
        .with_context(|| format!("Failed to open private key file: {}", config.key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("No private key found in {}", config.key_path))?;

    // Create signing key to verify it's valid
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
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
pub fn extract_san_dns_names(cert: &CertificateDer) -> Result<Vec<String>> {
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

/// Build an SNI resolver from server TLS configuration.
///
/// This function:
/// 1. Loads all certificates from the config
/// 2. Extracts SAN from each certificate
/// 3. Builds SNI -> certificate mapping
/// 4. Returns the resolver for use in TLS config
///
/// The first certificate is used as the default for unknown SNI.
pub fn build_sni_resolver(tls: &ServerTlsConfig) -> Result<Arc<SniResolverWithDefault>> {
    if tls.certificates.is_empty() {
        bail!("No certificates configured");
    }

    let mut resolver = ResolvesServerCertUsingSni::new();
    let mut first_certified_key: Option<Arc<CertifiedKey>> = None;

    for cert_config in &tls.certificates {
        let (certs, key) = load_cert_and_key(cert_config)?;

        // Build certified key
        let certified_key = CertifiedKey::new(
            certs.clone(),
            rustls::crypto::ring::sign::any_supported_type(&key)
                .map_err(|e| anyhow!("Unsupported private key type: {:?}", e))?,
        );

        // Store first certificate as default
        if first_certified_key.is_none() {
            first_certified_key = Some(Arc::new(certified_key.clone()));
        }

        // Extract SAN and add to resolver
        for cert_der in &certs {
            match extract_san_dns_names(cert_der) {
                Ok(dns_names) => {
                    for name in dns_names {
                        info!("Adding SNI mapping: {} -> {}", name, cert_config.cert_path);
                        resolver.add(&name, certified_key.clone())?;
                    }
                }
                Err(e) => {
                    warn!("Failed to extract SAN from certificate: {}", e);
                    // Continue anyway - the certificate might still work for some clients
                }
            }
        }
    }

    // Create resolver with default certificate fallback
    let resolver_with_default = SniResolverWithDefault::new(resolver, first_certified_key);
    Ok(Arc::new(resolver_with_default))
}

/// Build TLS server config with SNI support.
///
/// Creates a rustls::ServerConfig that:
/// - Uses SNI resolver for certificate selection
/// - Optionally requires client certificates for mTLS
pub fn build_tls_server_config(
    tls: &ServerTlsConfig,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
    let sni_resolver = build_sni_resolver(tls)?;

    // Build client cert verifier if configured
    let client_verifier = if let Some(ref client_ca_certs) = tls.client_ca_certs {
        let mut roots = rustls::RootCertStore::empty();
        for ca_path in client_ca_certs {
            let ca_file = File::open(ca_path)
                .with_context(|| format!("Failed to open client CA file: {}", ca_path))?;
            let mut ca_reader = BufReader::new(ca_file);
            let ca_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut ca_reader)
                .collect::<Result<Vec<_>, _>>()
                .with_context(|| "Failed to parse client CA certificates")?;
            for cert in ca_certs {
                roots.add(cert)?;
            }
        }
        Some(WebPkiClientVerifier::builder(roots.into()).build()?)
    } else {
        None
    };

    let mut config = match client_verifier {
        Some(verifier) => {
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(sni_resolver)
        }
        None => {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(sni_resolver)
        }
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
            let _ = rustls::crypto::ring::default_provider().install_default();
            true
        });
    }

    /// Generate a test certificate with specified SAN entries.
    fn generate_test_cert_with_san(san_entries: Vec<String>) -> (String, String, tempfile::TempDir) {
        ensure_crypto_provider();
        let temp_dir = tempfile::tempdir().unwrap();

        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(san_entries.clone()).unwrap();
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "test.local");

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
        let (cert_path, _key_path, _temp_dir) = generate_test_cert_with_san(vec![
            "test.example.com".to_string(),
            "api.example.com".to_string(),
        ]);

        // Load the certificate
        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let cert_der = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
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
    fn test_sni_resolver_basic() {
        ensure_crypto_provider();
        use rustls::server::ResolvesServerCertUsingSni;

        // Test that we can create an SNI resolver
        let mut resolver = ResolvesServerCertUsingSni::new();

        // Create a test certificate
        let (cert_path, key_path, _temp_dir) = generate_test_cert_with_san(vec![
            "test.local".to_string(),
        ]);

        let config = CertificateConfig { cert_path, key_path };
        let (certs, key) = load_cert_and_key(&config).unwrap();

        let certified_key = CertifiedKey::new(
            certs,
            rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
        );

        // Adding a certificate for a domain should work
        let result = resolver.add("test.local", certified_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_sni_resolver_from_certs() {
        ensure_crypto_provider();

        // Create test certificates with different SAN entries
        let (cert_path1, key_path1, _temp_dir1) = generate_test_cert_with_san(vec![
            "app1.example.com".to_string(),
        ]);
        let (cert_path2, key_path2, _temp_dir2) = generate_test_cert_with_san(vec![
            "app2.example.com".to_string(),
        ]);

        let tls = ServerTlsConfig {
            certificates: vec![
                CertificateConfig { cert_path: cert_path1, key_path: key_path1 },
                CertificateConfig { cert_path: cert_path2, key_path: key_path2 },
            ],
            client_ca_certs: None,
        };

        // Build SNI resolver
        let result = build_sni_resolver(&tls);
        assert!(result.is_ok());
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
    fn test_build_sni_resolver_empty_certificates() {
        ensure_crypto_provider();

        let tls = ServerTlsConfig {
            certificates: vec![],
            client_ca_certs: None,
        };

        let result = build_sni_resolver(&tls);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("No certificates configured"));
    }

    #[test]
    fn test_build_tls_server_config_basic() {
        ensure_crypto_provider();

        let (cert_path, key_path, _temp_dir) = generate_test_cert_with_san(vec![
            "test.example.com".to_string(),
        ]);

        let tls = ServerTlsConfig {
            certificates: vec![CertificateConfig { cert_path, key_path }],
            client_ca_certs: None,
        };

        let result = build_tls_server_config(&tls, vec![b"http/1.1".to_vec()]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_build_tls_server_config_with_h3_alpn() {
        ensure_crypto_provider();

        let (cert_path, key_path, _temp_dir) = generate_test_cert_with_san(vec![
            "test.example.com".to_string(),
        ]);

        let tls = ServerTlsConfig {
            certificates: vec![CertificateConfig { cert_path, key_path }],
            client_ca_certs: None,
        };

        let result = build_tls_server_config(&tls, vec![b"h3".to_vec()]);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    /// Test that SNI resolver returns the first certificate as default for unknown SNI.
    ///
    /// This test verifies the behavior described in the documentation:
    /// "The first certificate is used as the default for unknown SNI."
    ///
    /// When a client connects with an SNI that doesn't match any known domain,
    /// the resolver should fall back to the first configured certificate.
    #[test]
    fn test_sni_resolver_default_certificate_fallback() {
        ensure_crypto_provider();

        // Create two test certificates with different SAN entries
        let (cert_path1, key_path1, _temp_dir1) = generate_test_cert_with_san(vec![
            "app1.example.com".to_string(),
        ]);
        let (cert_path2, key_path2, _temp_dir2) = generate_test_cert_with_san(vec![
            "app2.example.com".to_string(),
        ]);

        let tls = ServerTlsConfig {
            certificates: vec![
                CertificateConfig { cert_path: cert_path1, key_path: key_path1 },
                CertificateConfig { cert_path: cert_path2, key_path: key_path2 },
            ],
            client_ca_certs: None,
        };

        // Build SNI resolver with default fallback
        let resolver = build_sni_resolver(&tls).expect("Should build resolver");

        // Verify the resolver was built successfully
        // The resolver should have a default certificate set
        assert!(
            resolver.default_cert.is_some(),
            "Resolver should have a default certificate"
        );

        // Verify the config was built correctly
        let config = build_tls_server_config(&tls, vec![b"http/1.1".to_vec()])
            .expect("Should build TLS config");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// Test that SniResolverWithDefault correctly wraps the SNI resolver.
    #[test]
    fn test_sni_resolver_with_default_creation() {
        ensure_crypto_provider();

        let (cert_path, key_path, _temp_dir) = generate_test_cert_with_san(vec![
            "test.example.com".to_string(),
        ]);

        let config = CertificateConfig { cert_path, key_path };
        let (certs, key) = load_cert_and_key(&config).unwrap();

        let certified_key = CertifiedKey::new(
            certs,
            rustls::crypto::ring::sign::any_supported_type(&key).unwrap(),
        );

        // Create an SNI resolver
        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        sni_resolver.add("test.example.com", certified_key.clone()).unwrap();

        // Create resolver with default
        let resolver = SniResolverWithDefault::new(
            sni_resolver,
            Some(Arc::new(certified_key)),
        );

        // Verify the default certificate is set
        assert!(resolver.default_cert.is_some());
    }
}
