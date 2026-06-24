#![allow(clippy::borrowed_box)]
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use anyhow::Result;
use tower::service_fn;

use crate::service::Service;

// ============================================================================
// Hostname Matching
// ============================================================================

/// Check if a hostname matches a pattern.
///
/// Pattern can be:
/// - Exact match: "api.example.com" matches exactly "api.example.com"
/// - Wildcard match: "*.example.com" matches "foo.example.com" but not
///   "example.com"
///
/// DNS matching is case-insensitive.
fn matches_hostname(pattern: &str, hostname: &str) -> bool {
  // DNS is case-insensitive
  let pattern_lower = pattern.to_lowercase();
  let hostname_lower = hostname.to_lowercase();

  // Exact match
  if pattern_lower == hostname_lower {
    return true;
  }

  // Wildcard match
  if let Some(suffix) = pattern_lower.strip_prefix("*.") {
    // hostname must end with .suffix and have exactly one additional
    // level
    if let Some(rest) =
      hostname_lower.strip_suffix(&format!(".{}", suffix))
    {
      // rest should not contain any dots (single level)
      return !rest.contains('.');
    }
  }

  false
}

/// Create a placeholder service for routing table initialization.
/// The actual service is selected at request time from the routing
/// table.
pub fn placeholder_service() -> Service {
  Service::new(service_fn(|_req| {
    Box::pin(async {
      Err::<Response, _>(anyhow::anyhow!("placeholder"))
    }) as Pin<Box<dyn Future<Output = Result<Response>>>>
  }))
}

// ============================================================================
// Shared-Address Listener Architecture (Task 020)
// ============================================================================

/// A server's routing info and its associated service.
#[derive(Clone)]
pub struct Server {
  /// Hostnames this server responds to
  pub hostnames: Vec<String>,
  /// The service to route requests to
  pub service: Service,
  /// Service name for logging
  pub service_name: String,
  /// Server-level TLS config (for https/http3)
  pub tls: Option<crate::config::ServerTlsConfig>,
}

impl Server {
  /// Get the service name for logging purposes.
  pub fn service_name(&self) -> String {
    self.service_name.clone()
  }

  /// Check whether this server requires client certificate
  /// authentication.
  ///
  /// Returns true if the server has TLS config with client CA
  /// certificates configured, meaning mTLS is required.
  pub fn requires_client_cert(&self) -> bool {
    self.tls.as_ref().and_then(|t| t.client_ca_certs.as_ref()).is_some()
  }
}

/// A router that encapsulates hostname-based routing logic.
///
/// Wraps a list of `Server` entries and provides efficient routing
/// by hostname, supporting exact matches, wildcard matches, and
/// default fallback.
#[derive(Clone)]
pub struct ServerRouter {
  servers: Vec<Rc<Server>>,
}

impl ServerRouter {
  /// Build a router from a list of servers.
  ///
  /// Each server is wrapped in `Rc` for cheap cloning during routing.
  pub fn build(servers: Vec<Server>) -> Self {
    let servers: Vec<Rc<Server>> =
      servers.into_iter().map(Rc::new).collect();
    Self { servers }
  }

  /// Route a request to the appropriate server based on hostname.
  ///
  /// Priority: exact match > wildcard match > default server (no
  /// hostnames). Returns `None` if no match is found.
  pub fn route(&self, hostname: Option<&str>) -> Option<Rc<Server>> {
    match hostname {
      Some(h) => {
        let mut wildcard_match: Option<Rc<Server>> = None;
        let mut default_server: Option<Rc<Server>> = None;

        for server in &self.servers {
          if server.hostnames.is_empty() {
            if default_server.is_none() {
              default_server = Some(server.clone());
            }
            continue;
          }

          for pattern in &server.hostnames {
            if matches_hostname(pattern, h) {
              if pattern.starts_with("*.") {
                if wildcard_match.is_none() {
                  wildcard_match = Some(server.clone());
                }
              } else {
                return Some(server.clone());
              }
            }
          }
        }
        wildcard_match.or(default_server)
      }
      None => {
        self.servers.iter().find(|s| s.hostnames.is_empty()).cloned()
      }
    }
  }
}

use crate::http_message::Response;
