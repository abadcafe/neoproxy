//! module: origin
//! responsibility: identify origins independently of transport
//! endpoints public operations:
//! Origin::{from_uri,host,port,is_https,authority}, Route, WireProtocol
//! data entities: Origin, Route, WireProtocol; tests: alt_svc_tests.rs,
//! dns_https_tests.rs

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct Origin {
  scheme: String,
  host: String,
  port: u16,
}

impl Origin {
  pub(super) fn from_uri(uri: &http::Uri) -> Option<Self> {
    let scheme = uri.scheme_str()?;
    if !matches!(scheme, "https" | "http") {
      return None;
    }
    let host = uri
      .host()?
      .trim_start_matches('[')
      .trim_end_matches(']')
      .trim_end_matches('.')
      .to_ascii_lowercase();
    Some(Self {
      scheme: scheme.to_owned(),
      host,
      port: uri.port_u16().unwrap_or(if scheme == "https" {
        443
      } else {
        80
      }),
    })
  }

  pub(super) fn host(&self) -> &str {
    &self.host
  }

  pub(super) fn port(&self) -> u16 {
    self.port
  }

  pub(super) fn is_https(&self) -> bool {
    self.scheme == "https"
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum WireProtocol {
  Http3,
  Http2,
  Http1,
  Negotiated,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct Route {
  pub(super) host: String,
  pub(super) port: u16,
  pub(super) protocol: WireProtocol,
}
impl Route {
  pub(super) fn authority(&self) -> String {
    authority(&self.host, self.port)
  }
}
fn authority(host: &str, port: u16) -> String {
  if host.contains(':') {
    format!("[{host}]:{port}")
  } else {
    format!("{host}:{port}")
  }
}
