//! module: dns_https
//! responsibility: discover origin endpoints through TTL-cached DNS
//! HTTPS records public operations:
//! DnsHttps::{new,routes,alternatives,addresses} data entities:
//! DnsHttps; tests: origin discovery process tests

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{
  ConnectionConfig, NameServerConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

use super::origin::{Origin, Route};
use super::service_binding::ServiceBinding;

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
    self
      .bindings(origin)
      .await
      .iter()
      .flat_map(ServiceBinding::routes)
      .collect()
  }

  async fn bindings(&self, origin: &Origin) -> Vec<ServiceBinding> {
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
      let bindings = self.bindings(&origin).await;
      if bindings.is_empty() {
        routes.push(alternative);
        continue;
      }
      routes.extend(
        bindings
          .iter()
          .filter_map(|binding| binding.alternative(&alternative)),
      );
    }
    routes
  }

  async fn discover(&self, origin: &Origin) -> Vec<ServiceBinding> {
    let mut name = if origin.port() == 443 {
      format!("{}.", origin.host())
    } else {
      format!("_{}._https.{}.", origin.port(), origin.host())
    };
    let mut visited = HashSet::new();
    let mut alias_fallback = None;
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
        // RFC 9460 §3: an SVCB-optional client must try the final
        // alias's address even if that name has no HTTPS records.
        alias_fallback = Some(ServiceBinding::fallback(
          name.trim_end_matches('.').to_owned(),
          origin.port(),
        ));
        continue;
      }
      return records
        .into_iter()
        .flat_map(|(owner, record)| {
          ServiceBinding::from_record(record, origin, &owner)
        })
        .chain(alias_fallback)
        .collect();
    }
    alias_fallback.into_iter().collect()
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
