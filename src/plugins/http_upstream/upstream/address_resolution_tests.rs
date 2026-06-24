use super::address_resolution::resolve_address;

#[tokio::test]
async fn test_resolve_address_ip_port() {
  let addr = resolve_address("127.0.0.1:8080").await.unwrap();
  assert_eq!(addr.port(), 8080);
}

#[tokio::test]
async fn test_resolve_address_invalid() {
  assert!(resolve_address("invalid").await.is_err());
}
