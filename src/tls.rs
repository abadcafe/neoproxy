//! module: tls
//! responsibility: construct listener-scoped TLS selection and
//! verification
//! public operations: build_tls_server_config, install_provider
//! data entities: TlsServer, SniResolver
//! tests: tls_selection_tests.rs, tls_tests.rs

//! TLS utilities for certificate loading and SNI routing.
//!
//! This module provides:
//! - Certificate loading from PEM files
//! - SNI-to-server selection with an explicit listener default
//! - Ordered selection from compiled server certificate candidates

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls::server::{
  ClientHello, ResolvesServerCert, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;

use crate::server::Server;

/// Per-listener virtual servers. A matched server without TLS remains
/// a match: it cannot silently fall back to another server's
/// certificate.
#[derive(Debug)]
struct TlsServer {
  certificates: Option<Arc<crate::certificate::Candidates>>,
}

#[derive(Debug, Default)]
struct SniResolver {
  exact: HashMap<String, Arc<TlsServer>>,
  wildcards: HashMap<String, Arc<TlsServer>>,
  default: Option<Arc<TlsServer>>,
}

impl SniResolver {
  fn compile(servers: &[Server]) -> Result<Self> {
    let mut resolver = Self::default();
    for (index, server) in servers.iter().enumerate() {
      let certificates = server
        .tls
        .as_ref()
        .map(|tls| tls.compile(&server.hostnames))
        .transpose()
        .with_context(|| {
          format!(
            "TLS server[{index}] (service '{}')",
            server.service_name
          )
        })?;
      let selected = Arc::new(TlsServer { certificates });
      if server.hostnames.is_empty() {
        ensure!(
          resolver.default.is_none(),
          "multiple default TLS servers"
        );
        resolver.default = Some(selected.clone());
      }
      for name in &server.hostnames {
        let name = crate::hostname::normalize(name);
        if let Some(suffix) = name.strip_prefix("*.") {
          ensure!(
            resolver
              .wildcards
              .insert(suffix.to_string(), selected.clone())
              .is_none(),
            "duplicate TLS hostname '{name}'"
          );
        } else {
          ensure!(
            resolver
              .exact
              .insert(name.clone(), selected.clone())
              .is_none(),
            "duplicate TLS hostname '{name}'"
          );
        }
      }
    }
    Ok(resolver)
  }
}

impl ResolvesServerCert for SniResolver {
  fn resolve(
    &self,
    hello: ClientHello<'_>,
  ) -> Option<Arc<CertifiedKey>> {
    let name = hello.server_name().map(crate::hostname::normalize);
    let selected = name
      .as_ref()
      .and_then(|name| {
        self.exact.get(name).or_else(|| {
          crate::hostname::wildcard_suffix(name)
            .and_then(|suffix| self.wildcards.get(suffix))
        })
      })
      .or(self.default.as_ref())?;
    selected.certificates.as_ref()?.choose(hello.signature_schemes())
  }
}

/// Build TLS server config with SNI support.
///
/// `servers` contains only the servers associated with this listener.
/// Their configured hostnames form this listener's SNI server index;
/// each server owns an ordered compiled certificate list. Their
/// client CA roots form one shared client trust domain for the
/// listener. No certificates or CA roots are collected from unrelated
/// listeners. SNI selects a server for certificate choice, while client
/// verification still uses the listener-wide CA union.
///
/// If client CA roots are configured, TLS authenticates any presented
/// client certificate against their union, while allowing clients to
/// omit a certificate. An untrusted presented certificate fails the
/// handshake; `allow_unauthenticated` does not waive its validation.
/// Omitted and empty CA path lists do not require client certificates.
/// After HTTP routing, a server with a nonempty `client_ca_certs` list
/// only requires that the connection presented a certificate. Requests
/// do not repeat chain verification or require authority to equal SNI.
pub(crate) fn build_tls_server_config(
  servers: &[Server],
  alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
  let sni_resolver = Arc::new(SniResolver::compile(servers)?);

  // Build this listener's shared client trust store from its servers.
  let mut roots = rustls::RootCertStore::empty();
  for (server_index, server) in servers.iter().enumerate() {
    let Some(tls) = &server.tls else {
      continue;
    };
    roots.roots.extend(
      tls
        .client_roots()
        .with_context(|| {
          format!(
            "TLS server[{server_index}] (service '{}')",
            server.service_name
          )
        })?
        .roots
        .iter()
        .cloned(),
    );
  }

  // Every configured CA file must contribute a certificate or fail
  // above. An empty store therefore means no CA paths were configured,
  // including when all servers use the default empty lists.
  let mut config = if !roots.is_empty() {
    // Certificate authentication stays in TLS. Anonymous connections
    // may finish the handshake so request routing can decide whether
    // a certificate is required; every presented certificate must pass
    // this listener's shared verifier.
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

/// Install the rustls crypto provider based on configuration.
pub(crate) fn install_provider(provider_name: &str) -> Result<()> {
  match provider_name {
    #[cfg(feature = "tls-openssl")]
    "openssl" => {
      rustls_openssl::default_provider().install_default().map_err(
        |_| {
          anyhow::anyhow!(
            "Failed to install rustls-openssl rustls crypto provider",
          )
        },
      )?;
      Ok(())
    }
    #[cfg(not(feature = "tls-openssl"))]
    "openssl" => {
      anyhow::bail!(
        "tls_provider 'openssl' requires the 'tls-openssl' cargo \
         feature"
      )
    }
    "ring" => {
      rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| {
          anyhow::anyhow!("Failed to install rustls crypto provider")
        })?;
      Ok(())
    }
    other => {
      anyhow::bail!(
        "Unknown tls_provider '{other}'. Supported: 'ring', 'openssl'"
      )
    }
  }
}
