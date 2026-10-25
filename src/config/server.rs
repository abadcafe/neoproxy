//! module: server
//! responsibilities: represent a configured virtual server
//! public operations: Server accessors
//! data entities: Server
//! tests: config_tests.rs via config's public interface
use serde::Deserialize;

use super::tls::ServerTlsConfig;

/// Server configuration.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Server {
  pub(in crate::config) name: String,
  /// Names used independently for TLS SNI server selection and HTTP
  /// authority/Host routing, within each associated listener. Empty
  /// names designate that listener's explicit default server.
  #[serde(default)]
  pub(in crate::config) hostnames: Vec<String>,
  /// TLS configuration (for https and http3 listeners)
  pub(in crate::config) tls: Option<ServerTlsConfig>,
  /// References to top-level listener names
  pub(in crate::config) listeners: Vec<String>,
  pub(in crate::config) service: String,
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
