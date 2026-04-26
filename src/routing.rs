//! Virtual host routing implementation.
//!
//! This module provides hostname-based routing for HTTP/HTTPS/HTTP3 listeners.
//! Routing priority: exact match > wildcard match > default server.

use tracing::warn;

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
        if let Some(rest) = hostname_lower.strip_suffix(&format!(".{}", suffix)) {
            // rest should not contain any dots (single level)
            return !rest.contains('.');
        }
    }

    false
}

/// Information about a server for routing purposes.
#[derive(Clone, Debug)]
pub struct ServerMatchInfo {
    /// Server name for logging
    pub name: String,
    /// Hostnames this server responds to
    /// Empty means default server
    pub hostnames: Vec<String>,
}

/// Find the matching server for a hostname.
///
/// Priority:
/// 1. Exact match
/// 2. Wildcard match
/// 3. Default server (empty hostnames)
///
/// Returns None if no match found.
pub fn find_matching_server<'a>(
    servers: &'a [ServerMatchInfo],
    hostname: &str,
) -> Option<&'a ServerMatchInfo> {
    let mut wildcard_match: Option<&ServerMatchInfo> = None;
    let mut default_server: Option<&ServerMatchInfo> = None;

    for server in servers {
        if server.hostnames.is_empty() {
            // Default server candidate
            if default_server.is_none() {
                default_server = Some(server);
            }
            continue;
        }

        for pattern in &server.hostnames {
            if matches_hostname(pattern, hostname) {
                if pattern.starts_with("*.") {
                    // Wildcard match - remember but continue looking for exact
                    if wildcard_match.is_none() {
                        wildcard_match = Some(server);
                    }
                } else {
                    // Exact match - return immediately
                    return Some(server);
                }
            }
        }
    }

    // Return wildcard if found, otherwise default
    wildcard_match.or(default_server)
}

/// Validate server hostname configuration.
///
/// Checks for:
/// - Multiple default servers (would cause ambiguity)
/// - Invalid wildcard patterns
pub fn validate_server_hostnames(
    servers: &[ServerMatchInfo],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut default_count = 0;

    for server in servers {
        if server.hostnames.is_empty() {
            default_count += 1;
            if default_count > 1 {
                errors.push(format!(
                    "Multiple default servers found (server '{}')",
                    server.name
                ));
            }
            continue;
        }

        for pattern in &server.hostnames {
            // Check for invalid wildcard patterns
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if suffix.is_empty() {
                    errors.push(format!(
                        "Invalid wildcard hostname '*' in server '{}'",
                        server.name
                    ));
                } else if !suffix.contains('.') {
                    // Valid: *.example.com
                    // Invalid: *.com (too broad)
                    warn!(
                        "Wildcard pattern '{}' in server '{}' may be too broad",
                        pattern, server.name
                    );
                }
            } else if pattern.contains('*') {
                errors.push(format!(
                    "Invalid hostname '{}' in server '{}': wildcard must be in format '*.domain'",
                    pattern, server.name
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
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

    #[test]
    fn test_find_matching_server_exact_priority() {
        let servers = vec![
            ServerMatchInfo {
                name: "wildcard".to_string(),
                hostnames: vec!["*.example.com".to_string()],
            },
            ServerMatchInfo {
                name: "exact".to_string(),
                hostnames: vec!["api.example.com".to_string()],
            },
        ];

        let result = find_matching_server(&servers, "api.example.com");
        assert_eq!(result.unwrap().name, "exact");
    }

    #[test]
    fn test_find_matching_server_wildcard_fallback() {
        let servers = vec![
            ServerMatchInfo {
                name: "wildcard".to_string(),
                hostnames: vec!["*.example.com".to_string()],
            },
            ServerMatchInfo {
                name: "exact".to_string(),
                hostnames: vec!["api.example.com".to_string()],
            },
        ];

        let result = find_matching_server(&servers, "other.example.com");
        assert_eq!(result.unwrap().name, "wildcard");
    }

    #[test]
    fn test_find_matching_server_default() {
        let servers = vec![
            ServerMatchInfo {
                name: "default".to_string(),
                hostnames: vec![],
            },
            ServerMatchInfo {
                name: "specific".to_string(),
                hostnames: vec!["api.example.com".to_string()],
            },
        ];

        let result = find_matching_server(&servers, "unknown.example.com");
        assert_eq!(result.unwrap().name, "default");
    }

    #[test]
    fn test_find_matching_server_no_match() {
        let servers = vec![
            ServerMatchInfo {
                name: "specific".to_string(),
                hostnames: vec!["api.example.com".to_string()],
            },
        ];

        let result = find_matching_server(&servers, "unknown.example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_server_hostnames_multiple_defaults() {
        let servers = vec![
            ServerMatchInfo {
                name: "default1".to_string(),
                hostnames: vec![],
            },
            ServerMatchInfo {
                name: "default2".to_string(),
                hostnames: vec![],
            },
        ];

        let result = validate_server_hostnames(&servers);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Multiple default servers"));
    }

    #[test]
    fn test_validate_server_hostnames_invalid_wildcard() {
        let servers = vec![
            ServerMatchInfo {
                name: "bad".to_string(),
                hostnames: vec!["*".to_string()],
            },
        ];

        let result = validate_server_hostnames(&servers);
        assert!(result.is_err());
    }
}
