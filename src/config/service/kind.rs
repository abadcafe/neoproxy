//! module: kind
//! responsibilities: parse a plugin-qualified configuration kind
//! public operations: parse_plugin_kind
//! data entities: none
//! tests: kind_tests.rs

/// Parse a `plugin_name.entity_name` kind string into (plugin_name,
/// entity_name).
///
/// Requires exactly one dot separator with non-empty parts on both
/// sides.
pub(super) fn parse_plugin_kind(
  kind: &str,
  entity_name: &str,
) -> anyhow::Result<(String, String)> {
  if kind.is_empty() {
    return Err(anyhow::anyhow!(
      "invalid {} kind '', expected 'plugin_name.{}_name'",
      entity_name,
      entity_name
    ));
  }
  let dot_count = kind.matches('.').count();
  if dot_count != 1 {
    return Err(anyhow::anyhow!(
      "invalid {} kind '{}', expected 'plugin_name.{}_name'",
      entity_name,
      kind,
      entity_name
    ));
  }
  let parts: Vec<&str> = kind.splitn(2, '.').collect();
  let plugin_name = parts[0];
  let name = parts[1];
  if plugin_name.is_empty() || name.is_empty() {
    return Err(anyhow::anyhow!(
      "invalid {} kind '{}', expected 'plugin_name.{}_name'",
      entity_name,
      kind,
      entity_name
    ));
  }
  Ok((plugin_name.to_string(), name.to_string()))
}
