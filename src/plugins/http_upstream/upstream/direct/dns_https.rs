//! module: dns_https
//! responsibility: discover origin endpoints through TTL-cached DNS
//! HTTPS records public operations: DnsHttps::{new,routes,addresses},
//! service_routes data entities: DnsHttps; tests: dns_https_tests.rs,
//! origin discovery process tests

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{
  ConnectionConfig, NameServerConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::rdata::svcb::{
  SVCB, SvcParamKey, SvcParamValue,
};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

use super::origin::{Origin, Route, WireProtocol};

pub(super) struct DnsHttps {
  resolver: TokioResolver,
  timeout: Duration,
}
impl DnsHttps {
  pub(super) fn new(
    servers: Option<&[SocketAddr]>,
    timeout: Duration,
  ) -> anyhow::Result<Self> {
    let mut builder = if let Some(servers) = servers {
      let servers = servers
        .iter()
        .map(|server| {
          let mut udp = ConnectionConfig::udp();
          udp.port = server.port();
          let mut tcp = ConnectionConfig::tcp();
          tcp.port = server.port();
          NameServerConfig::new(server.ip(), true, vec![udp, tcp])
        })
        .collect();
      Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
      )
    } else {
      Resolver::builder_tokio()?
    };
    builder.options_mut().timeout = timeout;
    builder.options_mut().attempts = 1;
    builder.options_mut().cache_size = 1024;
    Ok(Self { resolver: builder.build()?, timeout })
  }

  pub(super) async fn routes(&self, origin: &Origin) -> Vec<Route> {
    if !origin.is_https() || origin.host().parse::<IpAddr>().is_ok() {
      return Vec::new();
    }
    tokio::time::timeout(self.timeout, self.discover(origin))
      .await
      .unwrap_or_default()
  }

  /// RFC 9460 §9.3: cached Alt-Svc and HTTPS bindings constrain each
  /// other. DNS changes the endpoint, never the authenticated origin.
  pub(super) async fn alternatives(
    &self,
    advertised: Vec<Route>,
  ) -> Vec<Route> {
    let mut routes = Vec::new();
    for alternative in advertised {
      let Ok(uri) = format!("https://{}/", alternative.authority())
        .parse::<http::Uri>()
      else {
        continue;
      };
      let Some(origin) = Origin::from_uri(&uri) else {
        continue;
      };
      let bindings = self.routes(&origin).await;
      if bindings.is_empty() {
        routes.push(alternative);
        continue;
      }
      for mut binding in bindings {
        let compatible = match alternative.protocol {
          WireProtocol::Http3 => {
            binding.protocol == WireProtocol::Http3
          }
          WireProtocol::Http2
          | WireProtocol::Http1
          | WireProtocol::Negotiated => {
            binding.protocol == WireProtocol::Negotiated
          }
        };
        if compatible {
          binding.protocol = alternative.protocol;
          routes.push(binding);
        }
      }
    }
    routes
  }

  async fn discover(&self, origin: &Origin) -> Vec<Route> {
    let mut name = if origin.port() == 443 {
      format!("{}.", origin.host())
    } else {
      format!("_{}._https.{}.", origin.port(), origin.host())
    };
    let mut visited = HashSet::new();
    for _ in 0..8 {
      if !visited.insert(name.clone()) {
        break;
      }
      let Ok(lookup) =
        self.resolver.lookup(name.clone(), RecordType::HTTPS).await
      else {
        break;
      };
      let mut records = lookup
        .answers()
        .iter()
        .filter_map(|record| {
          if let RData::HTTPS(https) = &record.data {
            Some((record.name.to_ascii(), &https.0))
          } else {
            None
          }
        })
        .collect::<Vec<_>>();
      records.sort_by_key(|(_, record)| record.svc_priority);
      if let Some((_, alias)) =
        records.iter().find(|(_, record)| record.svc_priority == 0)
      {
        if alias.target_name.is_root() {
          break;
        }
        name = alias.target_name.to_ascii();
        continue;
      }
      return records
        .into_iter()
        .flat_map(|(owner, record)| {
          service_routes(record, origin, &owner)
        })
        .collect();
    }
    Vec::new()
  }

  pub(super) async fn addresses(
    &self,
    route: &Route,
  ) -> Vec<SocketAddr> {
    if let Ok(ip) = route.host.parse::<IpAddr>() {
      return vec![SocketAddr::new(ip, route.port)];
    }
    match tokio::time::timeout(
      self.timeout,
      self.resolver.lookup_ip(format!("{}.", route.host)),
    )
    .await
    {
      Ok(Ok(lookup)) => lookup
        .iter()
        .map(|ip| SocketAddr::new(ip, route.port))
        .collect(),
      _ => Vec::new(),
    }
  }
}

pub(super) fn service_routes(
  record: &SVCB,
  origin: &Origin,
  owner: &str,
) -> Vec<Route> {
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
      return Vec::new();
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
    return Vec::new();
  }
  let supports = |protocol: &str| {
    alpn
      .is_some_and(|protocols| protocols.iter().any(|p| p == protocol))
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
    return Vec::new();
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
  if !no_default || supports("h2") || supports("http/1.1") {
    protocols.push(WireProtocol::Negotiated);
  }
  protocols
    .into_iter()
    .map(|protocol| Route { host: host.clone(), port, protocol })
    .collect()
}
