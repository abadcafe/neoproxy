//! module: service_binding
//! responsibility: preserve DNS service protocol constraints until
//! route selection public operations: ServiceBinding::{from_record,
//! fallback, routes, alternative} data entities: ServiceBinding
//! tests: service_binding_tests.rs, service_binding_record_tests.rs

use hickory_resolver::proto::rr::rdata::svcb::{
  SVCB, SvcParamKey, SvcParamValue,
};

use super::origin::{Origin, Route, WireProtocol};

pub(super) struct ServiceBinding {
  host: String,
  port: u16,
  // None denotes an authority fallback without service parameters.
  protocols: Option<Vec<WireProtocol>>,
}

impl ServiceBinding {
  pub(super) fn from_record(
    record: &SVCB,
    origin: &Origin,
    owner: &str,
  ) -> Option<Self> {
    let params = &record.svc_params;
    for (_, value) in params {
      if let SvcParamValue::Mandatory(keys) = value
        && keys.0.iter().any(|key| {
          !matches!(
            key,
            SvcParamKey::Alpn
              | SvcParamKey::NoDefaultAlpn
              | SvcParamKey::Port
          ) || !params.iter().any(|(present, _)| present == key)
        })
      {
        return None;
      }
    }
    let no_default = params
      .iter()
      .any(|(_, value)| matches!(value, SvcParamValue::NoDefaultAlpn));
    let alpn = params.iter().find_map(|(_, value)| {
      if let SvcParamValue::Alpn(alpn) = value {
        Some(&alpn.0)
      } else {
        None
      }
    });
    if no_default && alpn.is_none() {
      return None;
    }
    let supports = |protocol: &str| {
      alpn.is_some_and(|protocols| {
        protocols.iter().any(|p| p == protocol)
      })
    };
    let port = params
      .iter()
      .find_map(|(_, value)| {
        if let SvcParamValue::Port(port) = value {
          Some(*port)
        } else {
          None
        }
      })
      .unwrap_or(origin.port());
    if port == 0 {
      return None;
    }
    let host = if record.target_name.is_root() {
      owner.trim_end_matches('.').to_owned()
    } else {
      record.target_name.to_ascii().trim_end_matches('.').to_owned()
    };
    let mut protocols = Vec::new();
    if supports("h3") {
      protocols.push(WireProtocol::Http3);
    }
    if supports("h2") {
      protocols.push(WireProtocol::Http2);
    }
    if !no_default || supports("http/1.1") {
      protocols.push(WireProtocol::Http1);
    }
    if protocols.is_empty() {
      return None;
    }
    Some(Self { host, port, protocols: Some(protocols) })
  }

  pub(super) fn fallback(host: String, port: u16) -> Self {
    Self { host, port, protocols: None }
  }

  pub(super) fn routes(&self) -> Vec<Route> {
    let Some(protocols) = &self.protocols else {
      return vec![self.route(WireProtocol::Negotiated)];
    };
    let mut routes = Vec::new();
    if protocols.contains(&WireProtocol::Http3) {
      routes.push(self.route(WireProtocol::Http3));
    }
    if protocols.iter().any(|protocol| {
      matches!(protocol, WireProtocol::Http1 | WireProtocol::Http2)
    }) {
      routes.push(self.route(WireProtocol::Negotiated));
    }
    routes
  }

  pub(super) fn alternative(
    &self,
    advertised: &Route,
  ) -> Option<Route> {
    self
      .protocols
      .as_ref()
      .is_none_or(|protocols| protocols.contains(&advertised.protocol))
      .then(|| self.route(advertised.protocol))
  }

  fn route(&self, protocol: WireProtocol) -> Route {
    Route { host: self.host.clone(), port: self.port, protocol }
  }
}
