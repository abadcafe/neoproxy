use std::time::Duration;

use super::defaults::{
  default_connect_timeout, default_dns_resolve_timeout,
  default_idle_timeout, default_keep_alive_interval,
  default_max_idle_per_host, default_tls_handshake_timeout,
  default_tunnel_idle_timeout, default_weight,
};

#[test]
fn test_default_weight_is_one() {
  assert_eq!(default_weight(), 1);
}

#[test]
fn test_default_timeouts_match_contract() {
  assert_eq!(default_connect_timeout(), Duration::from_secs(10));
  assert_eq!(default_tls_handshake_timeout(), Duration::from_secs(10));
  assert_eq!(default_tunnel_idle_timeout(), Duration::from_secs(60));
  assert_eq!(default_keep_alive_interval(), Duration::from_secs(3));
  assert_eq!(default_idle_timeout(), Duration::from_secs(90));
  assert_eq!(default_dns_resolve_timeout(), Duration::from_secs(5));
}

#[test]
fn test_default_pool_limit_matches_contract() {
  assert_eq!(default_max_idle_per_host(), 32);
}
