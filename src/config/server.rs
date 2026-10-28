//! module: server
//! responsibilities: represent a configured virtual server
//! public operations: Server accessors
//! data entities: Server, ServerFields
//! tests: server_tests.rs; config_tests.rs
use serde::Deserialize;

use super::tls::{CertificateConfig, ServerTlsConfig};

/// Server configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(from = "ServerFields")]
pub(crate) struct Server {
  pub(in crate::config) name: String,
  /// Names used independently for TLS SNI server selection and HTTP
  /// authority/Host routing, within each associated listener. Empty
  /// names designate that listener's explicit default server.
  pub(in crate::config) hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub(in crate::config) tls: Option<ServerTlsConfig>,
  /// References to top-level listener names
  pub(in crate::config) listeners: Vec<String>,
  pub(in crate::config) service: String,
}

/// YAML fields stay flat; runtime TLS compilation remains encapsulated.
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ServerFields {
  name: String,
  hostnames: Vec<String>,
  certificates: Option<Vec<CertificateConfig>>,
  client_ca_certs: Option<Vec<String>>,
  listeners: Vec<String>,
  service: String,
}

impl From<ServerFields> for Server {
  fn from(fields: ServerFields) -> Self {
    // Preserve explicitly configured empty/incomplete identities so
    // validation reports missing certificates instead of silently
    // disabling TLS.
    let tls = if fields.certificates.is_some()
      || fields.client_ca_certs.is_some()
    {
      Some(ServerTlsConfig::new(
        fields.certificates.unwrap_or_default(),
        fields.client_ca_certs.unwrap_or_default(),
      ))
    } else {
      None
    };
    Self {
      name: fields.name,
      hostnames: fields.hostnames,
      tls,
      listeners: fields.listeners,
      service: fields.service,
    }
  }
}

impl Server {
  pub(crate) fn name(&self) -> &str {
    &self.name
  }

  pub(crate) fn hostnames(&self) -> &[String] {
    &self.hostnames
  }

  pub(crate) fn tls(&self) -> Option<&ServerTlsConfig> {
    self.tls.as_ref()
  }

  pub(crate) fn listeners(&self) -> &[String] {
    &self.listeners
  }

  pub(crate) fn service(&self) -> &str {
    &self.service
  }
}
