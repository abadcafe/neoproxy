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
  32
}

pub(super) fn default_idle_timeout() -> Duration {
  Duration::from_secs(90)
}

pub(super) fn default_dns_resolve_timeout() -> Duration {
  Duration::from_secs(5)
}
