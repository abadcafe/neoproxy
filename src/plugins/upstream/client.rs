//! module: plugins::upstream::client
//! responsibility: construct and own configured upstream transport
//! pools
//! public operations: Upstream, forward, connect_for_tunnel,
//! UpstreamRegistry, new, get_upstream, contains_upstream, len,
//! tls_config, tracker, close_all
//! data entities: ScheduledClient, Upstream, UpstreamRegistry
//! tests: client_tests.rs

use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
pub(crate) use runtime::Upstream;
use rustls::pki_types::CertificateDer;

use super::config::{CertificateConfig, ClientCertCredential};
use super::error::UpstreamError;
use crate::tracker::StreamTracker;

// Sub-modules organized by protocol
mod connect_request;
#[cfg(test)]
mod connect_request_tests;
mod direct;
#[cfg(test)]
mod direct_tests;
mod dns_cache;
#[cfg(test)]
mod dns_cache_tests;
mod forward;
#[cfg(test)]
mod forward_tests;
mod http;
mod http1_framing;
#[cfg(test)]
mod http1_framing_tests;
mod http3;
#[cfg(test)]
mod http3_tests;
mod http_pool;
#[cfg(test)]
mod http_tests;
mod nodes;
#[cfg(test)]
mod nodes_tests;
mod observation;
#[cfg(test)]
mod observation_tests;
mod origin_connector;
#[cfg(test)]
mod origin_connector_tests;
pub(super) mod protocol;
mod proxy_auth;
#[cfg(test)]
mod proxy_auth_tests;
mod response;
#[cfg(test)]
mod response_tests;
mod retry_request;
mod runtime;
mod socks5;
#[cfg(test)]
mod socks5_tests;
mod tcp_connect;
#[cfg(test)]
mod tcp_connect_tests;
mod transport_factory;

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

// ============================================================================
// Upstream Registry
// ============================================================================

pub(crate) struct UpstreamRegistry {
  entries: HashMap<String, Rc<Upstream>>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  tracker: Rc<StreamTracker>,
}

impl UpstreamRegistry {
  pub(crate) fn new(
    upstreams: HashMap<String, super::config::Upstream>,
    certificates: Option<&CertificateConfig>,
    tracker: Rc<StreamTracker>,
  ) -> Result<Self> {
    let requires_tls = upstreams.values().any(|upstream| {
      upstream.addresses.is_empty()
        || upstream.addresses.iter().any(|address| {
          !matches!(
            address.address_protocol,
            super::config::Protocol::Http { .. }
              | super::config::Protocol::Socks5 { .. }
          )
        })
    });
    let tls_config = if !requires_tls && certificates.is_none() {
      None
    } else {
      let server_ca =
        certificates.and_then(|c| c.server_ca_path.as_deref());
      let roots = build_root_cert_store(server_ca)?;
      let ccc = match certificates {
        Some(certs) => {
          // Also validate certs to catch misconfigured client auth
          // early
          certs.validate()?;
          ClientCertCredential {
            cert_path: certs.client_cert_path.as_ref().map(Into::into),
            key_path: certs.client_key_path.as_ref().map(Into::into),
          }
        }
        None => {
          ClientCertCredential { cert_path: None, key_path: None }
        }
      };
      let mut client_config = build_tls_config(&ccc, roots)?;
      client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
      client_config.key_log = Arc::new(rustls::KeyLogFile::new());
      Some(Arc::new(client_config))
    };

    let mut entries: HashMap<String, Rc<Upstream>> = HashMap::new();

    let dns = upstreams
      .values()
      .next()
      .map(|config| {
        dns_cache::DnsCache::new(
          config.dns_servers.as_deref(),
          config.dns_resolve_timeout,
          config.dns_refresh_retry_interval,
        )
        .map(Rc::new)
      })
      .transpose()?;
    for (name, config) in upstreams {
      entries.insert(
        name,
        Rc::new(Upstream::new(
          config,
          dns.clone().expect("upstream DNS exists"),
          tls_config.clone(),
          tracker.clone(),
        )),
      );
    }

    Ok(Self { entries, tls_config, tracker })
  }

  pub(crate) fn get_upstream(
    &self,
    name: &str,
  ) -> Result<Rc<Upstream>, UpstreamError> {
    self
      .entries
      .get(name)
      .ok_or_else(|| {
        UpstreamError::ProxyInternalError(format!(
          "upstream '{name}' not found"
        ))
      })
      .cloned()
  }

  pub(crate) fn contains_upstream(&self, name: &str) -> bool {
    self.entries.contains_key(name)
  }

  pub(crate) fn len(&self) -> usize {
    self.entries.len()
  }

  pub(crate) fn tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
    self.tls_config.clone()
  }

  pub(crate) fn tracker(&self) -> Rc<StreamTracker> {
    self.tracker.clone()
  }

  pub(crate) fn close_all(&self) {
    for upstream in self.entries.values() {
      upstream.close();
    }
  }
}
