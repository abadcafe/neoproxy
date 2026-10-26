//! module: auth
//! responsibility: declare auth context fields
//! public operations: USER, AUTH_TYPE, PROXY_ID
//! data entities: none
//! tests: context_tests.rs and public plugin tests
use std::sync::Arc;

use super::super::key::ContextKey;
pub(crate) const USER: ContextKey<Arc<str>> =
  ContextKey::new("basic_auth.user");
pub(crate) const AUTH_TYPE: ContextKey<Arc<str>> =
  ContextKey::new("basic_auth.auth_type");
pub(crate) const PROXY_ID: ContextKey<Arc<str>> =
  ContextKey::new("proxy_id");
