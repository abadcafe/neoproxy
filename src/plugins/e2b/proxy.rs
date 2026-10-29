//! module: proxy
//! responsibility: compile E2B SOCKS5 proxy credentials and TLS trust
//! public operations: ProxyConfig::compile
//! data entities: ProxyConfig, TlsConfig
//! tests: proxy_tests.rs
use std::sync::Arc;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::plugins::upstream::egress::{Proxy, ProxyTls};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProxyConfig {
  address: String,
  username: Option<String>,
  password: Option<String>,
  tls: Option<TlsConfig>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TlsConfig {
  enabled: bool,
  server_name: Option<String>,
  ca_cert: Option<String>,
}
impl ProxyConfig {
  pub(super) fn compile(self) -> Result<Proxy> {
    let user = match (self.username, self.password) {
      (None, None) => None,
      (Some(username), Some(password)) => {
        ensure!(
          (1..=255).contains(&username.len())
            && (1..=255).contains(&password.len()),
          "SOCKS5 credentials require 1..=255 bytes"
        );
        Some(serde_json::from_value(
          serde_json::json!({"username":username,"password":password}),
        )?)
      }
      _ => {
        anyhow::bail!("egressProxy requires both username and password")
      }
    };
    let tls = self
      .tls
      .map(|tls| -> Result<Option<ProxyTls>> {
        if !tls.enabled {
          ensure!(
            tls.server_name.is_none() && tls.ca_cert.is_none(),
            "disabled proxy TLS cannot configure serverName or caCert"
          );
          return Ok(None);
        }
        let authority: http::uri::Authority = self.address.parse()?;
        let server_name = tls.server_name.unwrap_or_else(|| {
          authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
        });
        let _ =
          rustls::pki_types::ServerName::try_from(server_name.clone())?;
        let mut roots = rustls::RootCertStore::empty();
        if let Some(pem) = tls.ca_cert {
          ensure!(pem.len() <= 8192, "proxy caCert exceeds 8192 bytes");
          let certs = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<std::io::Result<Vec<_>>>()?;
          ensure!(
            !certs.is_empty(),
            "proxy caCert must contain certificates"
          );
          for cert in certs {
            roots.add(cert)?;
          }
        } else {
          for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert)?;
          }
        }
        let config = rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_no_client_auth();
        Ok(Some(ProxyTls { server_name, config: Arc::new(config) }))
      })
      .transpose()?
      .flatten();
    Proxy::new(self.address, user, tls)
  }
}
