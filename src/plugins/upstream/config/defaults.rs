//! module: plugins::upstream::config::defaults
//! responsibility: define upstream policy defaults
//! public operations: default_weight, default_connect_timeout,
//! default_tunnel_idle_timeout, default_tls_handshake_timeout,
//! default_keep_alive_interval, default_max_idle_per_host,
//! default_idle_timeout, default_dns_resolve_timeout
//! data entities: none
//! tests: defaults_tests.rs

use std::time::Duration;

pub(super) fn default_weight() -> usize {
  1
}

pub(super) fn default_connect_timeout() -> Duration {
  Duration::from_secs(10)
}

pub(super) fn default_tunnel_idle_timeout() -> Duration {
  Duration::from_secs(60)
}

pub(super) fn default_tls_handshake_timeout() -> Duration {
  Duration::from_secs(10)
}

pub(super) fn default_keep_alive_interval() -> Duration {
  Duration::from_secs(3)
}

pub(super) fn default_max_idle_per_host() -> usize {
  100
}

pub(super) fn default_idle_timeout() -> Duration {
  Duration::from_secs(60)
}

pub(super) fn default_dns_resolve_timeout() -> Duration {
  Duration::from_secs(5)
}
