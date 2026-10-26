//! module: hostname
//! responsibilities: canonicalize DNS names for routing
//! public operations: normalize, wildcard_suffix
//! data entities: none
//! tests: hostname_tests.rs

pub(crate) fn normalize(name: &str) -> String {
  let host = name
    .strip_prefix('[')
    .and_then(|name| name.strip_suffix(']'))
    .unwrap_or(name);
  if let Ok(address) = host.parse::<std::net::IpAddr>() {
    address.to_string()
  } else {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
  }
}

/// A wildcard consumes exactly one nonempty DNS label.
pub(crate) fn wildcard_suffix(name: &str) -> Option<&str> {
  if name.parse::<std::net::IpAddr>().is_ok() {
    return None;
  }
  let (label, suffix) = name.split_once('.')?;
  if label.is_empty() || suffix.is_empty() {
    None
  } else {
    Some(suffix)
  }
}
