//! module: certificate
//! responsibility: compile TLS certificate candidates and trust roots
//! public operations: Candidates::{load, validate_names, choose},
//! load_roots, load_root_file data entities: Candidates, Identity
//! tests: certificate_tests.rs and TLS process contracts

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};
use x509_parser::extensions::GeneralName;

use crate::hostname;

#[derive(Debug)]
struct Identity {
  path: String,
  key: Arc<CertifiedKey>,
  names: Vec<String>,
}

/// An ordered, immutable certificate snapshot. Names are used only to
/// validate configuration, never to create or select runtime routes.
#[derive(Debug)]
pub(crate) struct Candidates {
  identities: Vec<Identity>,
}

impl Candidates {
  pub(crate) fn load<'a>(
    paths: impl IntoIterator<Item = (&'a str, &'a str)>,
  ) -> Result<Self> {
    let mut identities = Vec::new();
    for (cert_path, key_path) in paths {
      identities.push(
        load_identity(cert_path, key_path).with_context(|| {
          format!("certificate '{cert_path}', key '{key_path}'")
        })?,
      );
    }
    ensure!(
      !identities.is_empty(),
      "at least one certificate is required"
    );
    Ok(Self { identities })
  }

  pub(crate) fn validate_names(
    &self,
    hostnames: &[String],
  ) -> Result<()> {
    for identity in &self.identities {
      for hostname in hostnames {
        let name = hostname::normalize(hostname);
        ensure!(
          identity.names.iter().any(|san| covers(san, &name)),
          "certificate '{}' does not cover hostname '{}'",
          identity.path,
          hostname
        );
      }
    }
    Ok(())
  }

  /// Rustls supplies compatible signature schemes, filtered against
  /// the peer's offered cipher suites before calling its resolver.
  /// Preserve certificate order, including candidates of the same type.
  pub(crate) fn choose(
    &self,
    schemes: &[SignatureScheme],
  ) -> Option<Arc<CertifiedKey>> {
    self
      .identities
      .iter()
      .find(|identity| {
        identity.key.key.choose_scheme(schemes).is_some()
      })
      .map(|identity| identity.key.clone())
  }
}

fn covers(san: &str, name: &str) -> bool {
  if name.starts_with("*.") {
    // Both routing and certificate wildcards consume one nonempty
    // label. A finite collection of exact SANs cannot cover that range.
    return san == name;
  }
  san == name
    || san.strip_prefix("*.").is_some_and(|suffix| {
      hostname::wildcard_suffix(name)
        .is_some_and(|actual| actual == suffix)
    })
}

fn load_identity(cert_path: &str, key_path: &str) -> Result<Identity> {
  let mut reader =
    BufReader::new(File::open(cert_path).context("read certificate")?);
  let certs = rustls_pemfile::certs(&mut reader)
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("parse certificate chain")?;
  let leaf = certs
    .first()
    .context("certificate file contains no certificates")?;
  let names = leaf_names(leaf)?;
  let mut reader =
    BufReader::new(File::open(key_path).context("read private key")?);
  let key = rustls_pemfile::private_key(&mut reader)
    .context("parse private key")?
    .context("private key file contains no key")?;
  let provider = rustls::crypto::CryptoProvider::get_default().expect(
    "CryptoProvider must be installed before compiling certificates",
  );
  // Use the provider's own consistency check, including its documented
  // handling of keys whose public part cannot be exported for
  // comparison.
  let key = CertifiedKey::from_der(certs, key, provider)
    .context("certificate/private key mismatch or unsupported key")?;
  Ok(Identity { path: cert_path.into(), key: Arc::new(key), names })
}

fn leaf_names(cert: &CertificateDer<'_>) -> Result<Vec<String>> {
  let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
    .map_err(|error| {
      anyhow::anyhow!("parse leaf certificate: {error}")
    })?;
  let mut names = Vec::new();
  if let Some(san) =
    parsed.subject_alternative_name().context("parse leaf SAN")?
  {
    for name in &san.value.general_names {
      match name {
        GeneralName::DNSName(name) => {
          let name = hostname::normalize(name);
          if !name.contains('*')
            || name.strip_prefix("*.").is_some_and(|suffix| {
              !suffix.contains('*') && !suffix.is_empty()
            })
          {
            names.push(name);
          }
        }
        GeneralName::IPAddress(address) => match *address {
          [a, b, c, d] => names
            .push(std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string()),
          bytes if bytes.len() == 16 => {
            let address: [u8; 16] =
              bytes.try_into().expect("checked IPv6 address length");
            names.push(std::net::Ipv6Addr::from(address).to_string());
          }
          _ => {}
        },
        _ => {}
      }
    }
  }
  Ok(names)
}

/// Every explicitly configured CA file must contribute a trusted root;
/// one valid file must never conceal an empty or malformed sibling
/// file.
pub(crate) fn load_roots(paths: &[String]) -> Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  for (index, path) in paths.iter().enumerate() {
    let loaded = load_root_file(path)
      .with_context(|| format!("client_ca_certs[{index}]"))?;
    roots.roots.extend(loaded.roots);
  }
  Ok(roots)
}

/// An explicitly configured trust file must contribute certificates.
/// Unrelated system or listener roots cannot conceal an empty file.
pub(crate) fn load_root_file(path: &str) -> Result<RootCertStore> {
  let load = || -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut reader =
      BufReader::new(File::open(path).context("read CA file")?);
    for cert in rustls_pemfile::certs(&mut reader) {
      roots
        .add(cert.context("parse CA certificate")?)
        .context("invalid CA certificate")?;
    }
    ensure!(!roots.is_empty(), "CA file contains no certificates");
    Ok(roots)
  };
  load().with_context(|| format!("CA file '{path}'"))
}
