//! module: plugins::http_upstream::inherit
//! responsibility: select inherited configuration values
//! public operations: resolve_field, resolve_field_with_default
//! data entities: none
//! tests: inherit_tests.rs

/// Resolve a field through three-level inheritance: address > upstream
/// > plugin. Returns the first `Some` value found.
pub(crate) fn resolve_field<T: Clone>(
  addr: Option<&T>,
  upstream: Option<&T>,
  plugin: Option<&T>,
) -> Option<T> {
  addr.or(upstream).or(plugin).cloned()
}

/// Like `resolve_field`, but falls back to a default if all levels are
/// `None`.
pub(crate) fn resolve_field_with_default<T: Clone>(
  addr: Option<&T>,
  upstream: Option<&T>,
  plugin: Option<&T>,
  default: T,
) -> T {
  resolve_field(addr, upstream, plugin).unwrap_or(default)
}
