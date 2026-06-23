use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use super::upstream::utils::resolve_address;
use super::upstream::{
  Address, Http3AddressState, Http3Client, QuicConfig, schedule_wrr,
};

fn dummy_http3() -> Http3Client {
  Http3Client {
    state: Rc::new(RefCell::new(Http3AddressState::new())),
    proxy_addr: String::new(),
    hostname: None,
    tls_handshake_timeout: Duration::from_secs(10),
    tunnel_idle_timeout: Duration::from_secs(60),
    dns_resolve_timeout: Duration::from_secs(5),
    quic: QuicConfig {
      max_idle_timeout: None,
      keep_alive_interval: Duration::from_secs(3),
      max_concurrent_bidi_streams: None,
      initial_mtu: None,
      send_window: None,
      receive_window: None,
    },
    user: None,
  }
}

fn dummy_address(weight: usize) -> Address {
  Address {
    weight,
    current_weight: Cell::new(0),
    client: Box::new(dummy_http3()),
  }
}

#[test]
fn test_schedule_wrr_single_address() {
  let addresses = vec![dummy_address(1)];
  assert_eq!(schedule_wrr(&addresses), Some(0));
}

#[test]
fn test_schedule_wrr_weighted() {
  let addresses = vec![
    dummy_address(3),
    Address {
      weight: 1,
      current_weight: Cell::new(0),
      client: Box::new(dummy_http3()),
    },
  ];
  let mut count_a = 0;
  let mut count_b = 0;
  for _ in 0..8 {
    match schedule_wrr(&addresses) {
      Some(0) => count_a += 1,
      Some(1) => count_b += 1,
      _ => panic!("unexpected index"),
    }
  }
  assert_eq!(count_a, 6);
  assert_eq!(count_b, 2);
}

#[test]
fn test_schedule_wrr_empty() {
  let addresses: Vec<Address> = vec![];
  assert_eq!(schedule_wrr(&addresses), None);
}

#[tokio::test]
async fn test_resolve_address_ip_port() {
  let addr = resolve_address("127.0.0.1:8080").await.unwrap();
  assert_eq!(addr.port(), 8080);
}

#[tokio::test]
async fn test_resolve_address_invalid() {
  assert!(resolve_address("invalid").await.is_err());
}
