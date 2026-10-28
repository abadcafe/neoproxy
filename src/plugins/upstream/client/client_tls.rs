//! module: client_tls
//! responsibility: construct TLS identity and trust for one connection
//! pool public operations: build
//! data entities: none
//! tests: client_tests.rs, named pool process contracts
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::pki_types::CertificateDer;

use crate::plugins::upstream::config::{
  CertificateConfig, ClientCertCredential,
};
fn build_root_cert_store(
  server_ca_path: Option<&str>,
) -> Result<rustls::RootCertStore> {
  let mut roots = rustls::RootCertStore::empty();
  let rustls_native_certs::CertificateResult { certs, errors, .. } =
    rustls_native_certs::load_native_certs();
  for cert in certs {
    if let Err(e) = roots.add(cert) {
      tracing::error!("failed to parse trust anchor: {e}");
    }
  }
  for e in errors {
    tracing::error!("couldn't load default trust roots: {e}");
  }
  if let Some(path) = server_ca_path {
    roots.roots.extend(
      crate::certificate::load_root_file(path)
        .context("server_ca_path")?
        .roots,
    );
  }
  Ok(roots)
}

fn build_tls_config(
  ccc: &ClientCertCredential,
  roots: rustls::RootCertStore,
) -> Result<rustls::ClientConfig> {
  match (&ccc.cert_path, &ccc.key_path) {
    (Some(cert_path), Some(key_path)) => {
      let cert_file = fs::File::open(cert_path)?;
      let mut cert_reader = BufReader::new(cert_file);
      let cert_chain: Vec<CertificateDer> =
        rustls_pemfile::certs(&mut cert_reader)
          .collect::<Result<Vec<_>, _>>()?;
      let key_file = fs::File::open(key_path)?;
      let mut key_reader = BufReader::new(key_file);
      let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("no private key found"))?;
      Ok(
        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_client_auth_cert(cert_chain, key)?,
      )
    }
    (None, None) => Ok(
      rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ),
    _ => bail!(
      "client_cert_path and client_key_path must both be present or \
       both absent"
    ),
  }
}

pub(super) fn build(
  certificates: Option<&CertificateConfig>,
) -> Result<Arc<rustls::ClientConfig>> {
  let roots = build_root_cert_store(
    certificates.and_then(|c| c.server_ca_path.as_deref()),
  )?;
  let credentials = ClientCertCredential {
    cert_path: certificates
      .and_then(|c| c.client_cert_path.as_ref())
      .map(Into::into),
    key_path: certificates
      .and_then(|c| c.client_key_path.as_ref())
      .map(Into::into),
  };
  let mut config = build_tls_config(&credentials, roots)?;
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  config.key_log = Arc::new(rustls::KeyLogFile::new());
  Ok(Arc::new(config))
}
