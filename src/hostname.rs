//! module: hostname
//! responsibilities: canonicalize DNS names for routing
//! public operations: normalize, wildcard_suffix
//! data entities: none
//! tests: hostname_tests.rs

pub(crate) fn normalize(name: &str) -> String {
  name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// A wildcard consumes exactly one nonempty DNS label.
pub(crate) fn wildcard_suffix(name: &str) -> Option<&str> {
  let (label, suffix) = name.split_once('.')?;
  if label.is_empty() || suffix.is_empty() {
    None
  } else {
    Some(suffix)
  }
}
