//! Black-box tests for tcp_bind module.

use std::net::SocketAddr;

use crate::listeners::tcp_bind::create_tcp_listener;

#[tokio::test]
async fn test_create_tcp_listener_ipv4_loopback_succeeds() {
  let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
  let result = create_tcp_listener(addr);
  assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_tcp_listener_ipv4_any_succeeds() {
  let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
  let result = create_tcp_listener(addr);
  assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_tcp_listener_ipv6_loopback_succeeds() {
  let addr: SocketAddr = "[::1]:0".parse().unwrap();
  let result = create_tcp_listener(addr);
  assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_tcp_listener_returns_valid_local_addr() {
  let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
  let listener = create_tcp_listener(addr).unwrap();
  let local_addr = listener.local_addr().unwrap();
  assert_eq!(local_addr.ip(), addr.ip());
  assert_ne!(local_addr.port(), 0); // port 0 -> assigned by OS
}
