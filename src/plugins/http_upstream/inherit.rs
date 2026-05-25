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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_resolve_field_address_wins() {
    assert_eq!(resolve_field(Some(&1), Some(&2), Some(&3)), Some(1));
  }

  #[test]
  fn test_resolve_field_upstream_fallback() {
    assert_eq!(resolve_field(None, Some(&2), Some(&3)), Some(2));
  }

  #[test]
  fn test_resolve_field_plugin_fallback() {
    assert_eq!(resolve_field(None, None, Some(&3)), Some(3));
  }

  #[test]
  fn test_resolve_field_all_none() {
    let result: Option<i32> = resolve_field(None, None, None);
    assert_eq!(result, None);
  }

  #[test]
  fn test_resolve_field_with_default_uses_address() {
    assert_eq!(
      resolve_field_with_default(Some(&1), Some(&2), Some(&3), 99),
      1
    );
  }

  #[test]
  fn test_resolve_field_with_default_uses_default() {
    assert_eq!(resolve_field_with_default(None, None, None, 99), 99);
  }
}
