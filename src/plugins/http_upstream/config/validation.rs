use anyhow::{Context, Result, anyhow, bail};

/// Validate that an address string has host:port format without DNS
/// resolution.
pub(crate) fn validate_address_format(s: &str) -> Result<()> {
  let colon_pos = s
    .rfind(':')
    .ok_or_else(|| anyhow!("address '{s}' missing port"))?;
  let port_str = &s[colon_pos + 1..];
  port_str
    .parse::<u16>()
    .with_context(|| format!("address '{s}' has invalid port"))?;
  let host = &s[..colon_pos];
  if host.is_empty() {
    bail!("address '{s}' missing host");
  }
  Ok(())
}
