use std::net::IpAddr;

use super::policy::Policy;

fn policy(json: &str) -> Policy {
  Policy::parse(serde_json::from_str(json).unwrap()).unwrap()
}

#[test]
fn test_parse_allow_precedes_deny_and_default_allows() {
  let p = policy(
    r#"{"allowOut":["10.1.0.0/16"],"denyOut":["0.0.0.0/0","::/0"]}"#,
  );
  assert!(p.allows_ip("10.1.2.3".parse().unwrap()));
  assert!(!p.allows_ip("10.2.2.3".parse().unwrap()));
  assert!(!p.allows_ip("::1".parse().unwrap()));
  assert!(policy("{}").allows_ip("127.0.0.1".parse().unwrap()));
}

#[test]
fn test_parse_domain_patterns_and_dns_access() {
  let p = policy(
    r#"{"allowOut":["Example.com","*.example.org"],"denyOut":["0.0.0.0/0"]}"#,
  );
  assert!(p.allows_domain("EXAMPLE.COM."));
  assert!(p.allows_domain("a.b.example.org"));
  assert!(!p.allows_domain("example.org"));
  assert!(!p.allows_domain("badexample.org"));
  assert!(p.allows_ip("8.8.8.8".parse().unwrap()));
  let p = policy(
    r#"{"allowOut":["example.com"],"dnsServers":[],"denyOut":["0.0.0.0/0"]}"#,
  );
  assert!(!p.allows_ip("8.8.8.8".parse().unwrap()));
}

#[test]
fn test_parse_explicit_dns_and_ipv6_mapped_addresses() {
  let p = policy(
    r#"{"allowOut":["example.com"],"dnsServers":["1.1.1.1"],"denyOut":["127.0.0.0/8"]}"#,
  );
  assert!(p.allows_ip("1.1.1.1".parse().unwrap()));
  assert!(!p.allows_ip("::ffff:127.0.0.1".parse().unwrap()));
  assert!(!Policy::domain_address_allowed(
    "::ffff:127.0.0.1".parse::<IpAddr>().unwrap()
  ));
  assert!(!Policy::domain_address_allowed(
    "169.254.169.254".parse().unwrap()
  ));
  assert!(Policy::domain_address_allowed("1.1.1.1".parse().unwrap()));
}

#[test]
fn test_parse_rejects_invalid_and_unsupported_policy() {
  for json in [
    r#"{"denyOut":["example.com"]}"#,
    r#"{"allowOut":["bad name"]}"#,
    r#"{"dnsServers":["::1"]}"#,
    r#"{"egressProxy":{"address":"host"}}"#,
    r#"{"rules":{"example.com":[{"transform":{"headers":{}}}]}}"#,
    r#"{"unknown":true}"#,
  ] {
    assert!(
      Policy::parse(serde_json::from_str(json).unwrap()).is_err(),
      "{json}"
    );
  }
}

#[test]
fn test_parse_ipv6_denials_cover_mapped_ipv6_without_blocking_ipv4() {
  let p = policy(r#"{"denyOut":["::/0"]}"#);
  assert!(!p.allows_ip("::ffff:1.1.1.1".parse().unwrap()));
  assert!(p.allows_ip("1.1.1.1".parse().unwrap()));
  for json in [
    r#"{"allowInternetAccess":false}"#,
    r#"{"allow_internet_access":false}"#,
  ] {
    let p = policy(json);
    assert!(!p.allows_ip("1.1.1.1".parse().unwrap()));
    assert!(!p.allows_ip("2606:4700:4700::1111".parse().unwrap()));
  }
}
