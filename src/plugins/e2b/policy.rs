//! module: policy
//! responsibility: compile and evaluate E2B outbound destination
//! policies public operations:
//! Policy::{parse,allows_ip,allows_domain,proxy,
//! domain_address_allowed} data entities: Policy, Document, Network,
//! DomainPattern, Rule tests: policy_tests.rs
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use super::proxy::ProxyConfig;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
  #[serde(default)]
  allow_out: Vec<String>,
  #[serde(default)]
  deny_out: Vec<String>,
  dns_servers: Option<Vec<Ipv4Addr>>,
  egress_proxy: Option<ProxyConfig>,
  #[serde(default)]
  rules: std::collections::BTreeMap<String, Vec<Rule>>,
  #[serde(alias = "allow_internet_access")]
  allow_internet_access: Option<bool>,
}

// Rules currently contain only transform in E2B. Transform is
// deliberately unsupported: reject it instead of silently claiming to
// apply credentials.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Rule {}

#[derive(Clone, Debug)]
struct Network {
  address: IpAddr,
  prefix: u8,
}
impl Network {
  fn parse(value: &str) -> Result<Self> {
    let (address, prefix) = match value.split_once('/') {
      Some((address, prefix)) => {
        (address.parse::<IpAddr>()?, Some(prefix.parse::<u8>()?))
      }
      None => (value.parse::<IpAddr>()?, None),
    };
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(bits);
    ensure!(prefix <= bits, "invalid CIDR prefix");
    Ok(Self { address, prefix })
  }

  fn contains(&self, ip: IpAddr) -> bool {
    match (self.address, ip) {
      (IpAddr::V4(a), ip) if canonical(ip).is_ipv4() => {
        let IpAddr::V4(b) = canonical(ip) else {
          unreachable!("canonical IPv4 address")
        };
        self.prefix == 0
          || u32::from(a) >> (32 - self.prefix)
            == u32::from(b) >> (32 - self.prefix)
      }
      (IpAddr::V6(a), IpAddr::V6(b)) => {
        self.prefix == 0
          || u128::from(a) >> (128 - self.prefix)
            == u128::from(b) >> (128 - self.prefix)
      }
      _ => false,
    }
  }
}
#[derive(Clone, Debug)]
struct DomainPattern(String);
impl DomainPattern {
  fn parse(value: &str) -> Result<Self> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    let name = value.strip_prefix("*.").unwrap_or(&value);
    ensure!(
      value == "*"
        || (!name.is_empty()
          && name.len() <= 253
          && name.split('.').all(|label| !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
              .bytes()
              .all(|b| b.is_ascii_alphanumeric() || b == b'-'))),
      "invalid domain pattern"
    );
    Ok(Self(value))
  }

  fn matches(&self, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    self.0 == "*"
      || self.0 == name
      || self.0.strip_prefix('*').is_some_and(|suffix| {
        name.len() > suffix.len() && name.ends_with(suffix)
      })
  }
}
#[derive(Debug)]
pub(super) struct Policy {
  allowed: Vec<Network>,
  denied: Vec<Network>,
  domains: Vec<DomainPattern>,
  proxy:
    Option<std::sync::Arc<crate::plugins::upstream::egress::Proxy>>,
}
impl Policy {
  pub(super) fn parse(value: serde_json::Value) -> Result<Self> {
    let doc: Document = serde_json::from_value(value)?;
    anyhow::ensure!(
      doc
        .dns_servers
        .as_ref()
        .is_none_or(|servers| servers.len() <= 10),
      "dnsServers supports at most 10 addresses"
    );
    let mut allowed = Vec::new();
    let mut domains = Vec::new();
    for value in doc.allow_out {
      match Network::parse(&value) {
        Ok(network) => allowed.push(network),
        Err(_) => domains.push(DomainPattern::parse(&value)?),
      }
    }
    for key in doc.rules.keys() {
      let _ = DomainPattern::parse(key)?;
    }
    if !domains.is_empty() {
      let servers = doc
        .dns_servers
        .unwrap_or_else(|| vec![Ipv4Addr::new(8, 8, 8, 8)]);
      ensure!(
        servers.len() <= 10,
        "dnsServers supports at most 10 addresses"
      );
      for ip in servers {
        allowed.push(Network { address: IpAddr::V4(ip), prefix: 32 });
      }
    }
    let mut denied = doc
      .deny_out
      .iter()
      .map(|v| Network::parse(v))
      .collect::<Result<Vec<_>>>()?;
    if doc.allow_internet_access == Some(false) {
      denied.push(Network::parse("0.0.0.0/0")?);
      denied.push(Network::parse("::/0")?);
    }
    let proxy = doc
      .egress_proxy
      .map(ProxyConfig::compile)
      .transpose()?
      .map(std::sync::Arc::new);
    Ok(Self { allowed, denied, domains, proxy })
  }

  pub(super) fn allows_ip(&self, ip: IpAddr) -> bool {
    self.allowed.iter().any(|n| n.contains(ip))
      || !self.denied.iter().any(|n| n.contains(ip))
  }

  pub(super) fn allows_domain(&self, host: &str) -> bool {
    !host.is_empty()
      && host.parse::<IpAddr>().is_err()
      && self.domains.iter().any(|pattern| pattern.matches(host))
  }

  pub(super) fn proxy(
    &self,
  ) -> Option<std::sync::Arc<crate::plugins::upstream::egress::Proxy>>
  {
    self.proxy.clone()
  }

  pub(super) fn domain_address_allowed(ip: IpAddr) -> bool {
    match canonical(ip) {
      IpAddr::V4(ip) => {
        !ip.is_private()
          && !ip.is_loopback()
          && !ip.is_link_local()
          && !ip.is_unspecified()
          && !ip.is_multicast()
          && !ip.is_broadcast()
          && !(ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
      }
      IpAddr::V6(ip) => {
        !ip.is_loopback()
          && !ip.is_unspecified()
          && !ip.is_unique_local()
          && !ip.is_unicast_link_local()
          && !ip.is_multicast()
      }
    }
  }
}
fn canonical(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(ip) => {
      ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
    }
    ip => ip,
  }
}

impl crate::plugins::upstream::egress::DestinationPolicy for Policy {
  fn allows(&self, host: &str, ip: IpAddr) -> bool {
    if self.allows_domain(host) {
      Self::domain_address_allowed(ip)
    } else {
      self.allows_ip(ip)
    }
  }
}
