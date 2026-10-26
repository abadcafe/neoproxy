//! module: dns
//! responsibility: declare dns context fields
//! public operations: HOST, TIME, ADDRESSES, DEADLINE
//! data entities: none
//! tests: context_tests.rs and public plugin tests
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::super::key::ContextKey;
pub(crate) const HOST: ContextKey<Arc<str>> =
  ContextKey::new("upstream.dns.host");
pub(crate) const TIME: ContextKey<Duration> =
  ContextKey::new("upstream.dns.duration_ms");
pub(crate) const ADDRESSES: ContextKey<Arc<[IpAddr]>> =
  ContextKey::new("upstream.dns.addresses");
pub(crate) const DEADLINE: ContextKey<Duration> =
  ContextKey::new("upstream.dns.timeout_ms");
