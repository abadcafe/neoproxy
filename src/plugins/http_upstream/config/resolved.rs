use std::path;
use std::time::Duration;

use super::raw::PoolConfig;
use crate::config::UserCredential;

/// Client certificate credential for TLS authentication.
#[derive(Clone, Debug)]
pub(crate) struct ClientCertCredential {
  pub(crate) cert_path: Option<path::PathBuf>,
  pub(crate) key_path: Option<path::PathBuf>,
}

/// Protocol identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolKind {
  Http,
  Https,
  Http3,
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

/// Resolved address after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct Address {
  pub(crate) address: String,
  pub(crate) hostname: Option<String>,
  pub(crate) weight: usize,
  pub(crate) protocol: Protocol,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) user: Option<UserCredential>,
}

/// Resolved upstream after three-level inheritance.
#[derive(Clone, Debug)]
pub(crate) struct Upstream {
  pub(crate) addresses: Vec<Address>,
  pub(crate) pool_config: PoolConfig,
  /// Direct-mode fields (used when addresses is empty):
  pub(crate) connect_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
}
