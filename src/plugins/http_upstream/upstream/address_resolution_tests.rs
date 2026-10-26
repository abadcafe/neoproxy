use super::address_resolution::resolve_addresses;

#[tokio::test]
async fn test_resolve_addresses_ip_port_returns_single_candidate() {
  let addrs = resolve_addresses("127.0.0.1:8080").await.unwrap();
  assert_eq!(addrs.len(), 1);
  assert_eq!(addrs[0].port(), 8080);
}

#[tokio::test]
async fn test_resolve_addresses_invalid() {
  assert!(resolve_addresses("invalid").await.is_err());
}

#[tokio::test]
async fn test_resolve_addresses_localhost_preserves_port() {
  let addresses = resolve_addresses("localhost:8123").await.unwrap();
  assert!(!addresses.is_empty());
  assert!(addresses.iter().all(
    |address| address.ip().is_loopback() && address.port() == 8123
  ));
}

#[tokio::test]
async fn test_timeout_resolver_localhost_resolves_within_deadline() {
  use tower::Service;
  let mut resolver = super::address_resolution::TimeoutResolver::new(
    std::time::Duration::from_secs(1),
  );
  let name = "localhost".parse().unwrap();
  let addresses: Vec<_> = resolver.call(name).await.unwrap().collect();
  assert!(!addresses.is_empty());
  assert!(addresses.iter().all(|address| address.ip().is_loopback()));
}
