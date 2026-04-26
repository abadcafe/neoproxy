//! Virtual host routing implementation.
//!
//! This module provides hostname-based routing for HTTP/HTTPS/HTTP3 listeners.
//! Routing priority: exact match > wildcard match > default server.

/// Check if a hostname matches a pattern.
///
/// Pattern can be:
/// - Exact match: "api.example.com" matches exactly "api.example.com"
/// - Wildcard match: "*.example.com" matches "foo.example.com" but not "example.com"
///
/// DNS matching is case-insensitive.
pub fn matches_hostname(pattern: &str, hostname: &str) -> bool {
  // DNS is case-insensitive
  let pattern_lower = pattern.to_lowercase();
  let hostname_lower = hostname.to_lowercase();

  // Exact match
  if pattern_lower == hostname_lower {
    return true;
  }

  // Wildcard match
  if let Some(suffix) = pattern_lower.strip_prefix("*.") {
    // hostname must end with .suffix and have exactly one additional level
    if let Some(rest) =
      hostname_lower.strip_suffix(&format!(".{}", suffix))
    {
      // rest should not contain any dots (single level)
      return !rest.contains('.');
    }
  }

  false
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_matches_hostname_exact() {
    assert!(matches_hostname("api.example.com", "api.example.com"));
    assert!(!matches_hostname("api.example.com", "other.example.com"));
  }

  #[test]
  fn test_matches_hostname_wildcard() {
    assert!(matches_hostname("*.example.com", "foo.example.com"));
    assert!(matches_hostname("*.example.com", "bar.example.com"));
    // Wildcard should NOT match the base domain
    assert!(!matches_hostname("*.example.com", "example.com"));
    // Wildcard should NOT match multiple levels
    assert!(!matches_hostname("*.example.com", "foo.bar.example.com"));
  }

  #[test]
  fn test_matches_hostname_case_insensitive() {
    // DNS is case-insensitive
    assert!(matches_hostname("API.EXAMPLE.COM", "api.example.com"));
    assert!(matches_hostname("*.EXAMPLE.COM", "foo.example.com"));
    assert!(matches_hostname("api.example.com", "API.EXAMPLE.COM"));
  }
}
