use super::inherit::*;

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
