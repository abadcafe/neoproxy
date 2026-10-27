//! module: upstream
//! responsibility: declare upstream context fields
//! public operations: FORWARD_TIME, FORWARD_STATUS, CONNECT_TIME,
//! ERROR_PHASE, ERROR_KIND, ERROR_MESSAGE, PROTOCOL data entities: none
//! tests: context_tests.rs and public plugin tests
use std::sync::Arc;
use std::time::Duration;

use super::super::key::ContextKey;
pub(crate) const FORWARD_TIME: ContextKey<Duration> =
  ContextKey::new("upstream.forward_ms");
pub(crate) const FORWARD_STATUS: ContextKey<u64> =
  ContextKey::new("upstream.forward_status");
pub(crate) const CONNECT_TIME: ContextKey<Duration> =
  ContextKey::new("upstream.connect_ms");
pub(crate) const ERROR_PHASE: ContextKey<Arc<str>> =
  ContextKey::new("upstream.error.phase");
pub(crate) const ERROR_KIND: ContextKey<Arc<str>> =
  ContextKey::new("upstream.error.kind");
pub(crate) const ERROR_MESSAGE: ContextKey<Arc<str>> =
  ContextKey::new("upstream.error.message");
pub(crate) const PROTOCOL: ContextKey<Arc<str>> =
  ContextKey::new("upstream.protocol");
