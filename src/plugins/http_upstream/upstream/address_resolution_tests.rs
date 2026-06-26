use super::address_resolution::{resolve_address, resolve_addresses};

#[tokio::test]
async fn test_resolve_address_ip_port() {
  let addr = resolve_address("127.0.0.1:8080").await.unwrap();
  assert_eq!(addr.port(), 8080);
}

#[tokio::test]
async fn test_resolve_addresses_ip_port_returns_single_candidate() {
  let addrs = resolve_addresses("127.0.0.1:8080").await.unwrap();
  assert_eq!(addrs.len(), 1);
  assert_eq!(addrs[0].port(), 8080);
}

#[tokio::test]
async fn test_resolve_address_invalid() {
  assert!(resolve_address("invalid").await.is_err());
}
