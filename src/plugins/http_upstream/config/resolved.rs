//! module: plugins::http_upstream::config::resolved
//! responsibility: describe fully resolved upstream transports
//! public operations: ClientCertCredential, QuicResolved, Protocol,
//! Address, Upstream
//! data entities: ClientCertCredential, QuicResolved, Protocol,
//! Address, Upstream
//! tests: resolved_tests.rs

use std::path;
use std::time::Duration;

use super::protocol::{PoolConfig, ProtocolKind};
use crate::config::UserCredential;

/// Client certificate credential for TLS authentication.
#[derive(Clone, Debug)]
pub(crate) struct ClientCertCredential {
  pub(crate) cert_path: Option<path::PathBuf>,
  pub(crate) key_path: Option<path::PathBuf>,
}

/// Resolved QUIC config from field-level three-level merge.
#[derive(Clone, Debug)]
pub(crate) struct QuicResolved {
  pub(crate) max_idle_timeout: Option<Duration>,
  pub(crate) keep_alive_interval: Duration,
  pub(crate) max_concurrent_bidi_streams: Option<u64>,
  pub(crate) initial_mtu: Option<u16>,
  pub(crate) send_window: Option<u64>,
  pub(crate) receive_window: Option<u64>,
}

/// Resolved protocol with all fields filled.
#[derive(Clone, Debug)]
pub(crate) enum Protocol {
  Http { connect_timeout: Duration },
  Https { connect_timeout: Duration, tls_handshake_timeout: Duration },
  Http3 { tls_handshake_timeout: Duration, quic: QuicResolved },
}

impl Protocol {
  pub(crate) fn kind(&self) -> ProtocolKind {
    match self {
      Self::Http { .. } => ProtocolKind::Http,
      Self::Https { .. } => ProtocolKind::Https,
      Self::Http3 { .. } => ProtocolKind::Http3,
    }
  }
}

/// Resolved address after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct Address {
  pub(crate) address_max_fails: usize,
  pub(crate) address_fail_timeout: Duration,
  pub(crate) tcp_keep_alive_time: Option<Duration>,
  pub(crate) tcp_keep_alive_interval: Option<Duration>,
  pub(crate) tcp_keep_alive_retries: Option<u32>,

  pub(crate) address: String,
  pub(crate) hostname: Option<String>,
  pub(crate) weight: usize,
  pub(crate) address_protocol: Protocol,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) upstream_request_timeout: Duration,
  pub(crate) user: Option<UserCredential>,
}

/// Resolved upstream after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct Upstream {
  pub(crate) address_max_fails: usize,
  pub(crate) address_fail_timeout: Duration,
  pub(crate) tcp_keep_alive_time: Option<Duration>,
  pub(crate) tcp_keep_alive_interval: Option<Duration>,
  pub(crate) tcp_keep_alive_retries: Option<u32>,
  pub(crate) dns_refresh_retry_interval: Duration,
  pub(crate) dns_servers: Option<Vec<std::net::SocketAddr>>,
  pub(crate) addresses: Vec<Address>,
  pub(crate) pool_config: PoolConfig,
  /// Direct-mode fields (used when addresses is empty):
  pub(crate) connect_timeout: Duration,
  pub(crate) tls_handshake_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
  pub(crate) upstream_request_timeout: Duration,
}
