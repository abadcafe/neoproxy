//! module: connection
//! responsibility: declare connection context fields
//! public operations: PEER, LOCAL, REUSED, CONNECT_TIME, TLS_TIME,
//! ALPN, PROTOCOL data entities: none
//! tests: context_tests.rs and public plugin tests
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use super::super::key::ContextKey;
pub(crate) const PEER: ContextKey<SocketAddr> =
  ContextKey::new("upstream.connection.peer");
pub(crate) const LOCAL: ContextKey<SocketAddr> =
  ContextKey::new("upstream.connection.local");
pub(crate) const REUSED: ContextKey<bool> =
  ContextKey::new("upstream.connection.reused");
pub(crate) const CONNECT_TIME: ContextKey<Duration> =
  ContextKey::new("upstream.tcp.connect_ms");
pub(crate) const TLS_TIME: ContextKey<Duration> =
  ContextKey::new("upstream.tls.handshake_ms");
pub(crate) const ALPN: ContextKey<Arc<str>> =
  ContextKey::new("upstream.tls.alpn");
pub(crate) const PROTOCOL: ContextKey<Arc<str>> =
  ContextKey::new("upstream.protocol");
