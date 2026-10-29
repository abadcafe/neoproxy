//! module: server
//! responsibility: select services by canonical hostname
//! public operations: Server,
//! requires_client_cert, ServerRouter, build, route
//! data entities: Server, ServerRouter, Routes
//! tests: server_tests.rs, server_thread_tests.rs

use std::rc::Rc;

use crate::service::Service;

// ============================================================================
// Shared-Address Listener Architecture (Task 020)
// ============================================================================

/// A server's routing info and its associated service.
#[derive(Clone)]
pub(crate) struct Server {
  /// Hostnames this server responds to
  pub(crate) hostnames: Vec<String>,
  /// The service to route requests to
  pub(crate) service: Service,
  /// Service name for logging
  pub(crate) service_name: String,
  /// Server-level TLS config (for https/http3)
  pub(crate) tls: Option<crate::config::ServerTlsConfig>,
}

impl Server {
  /// Whether HTTPS/H3 requests routed here require an authenticated
  /// client connection. TLS has already validated any presented client
  /// certificate against the listener's combined CA roots. This is a
  /// presence requirement for a nonempty CA path list; omitted and
  /// empty lists do not require a client certificate. Each listener
  /// still has a shared trust domain across its associated servers.
  pub(crate) fn requires_client_cert(&self) -> bool {
    self
      .tls
      .as_ref()
      .is_some_and(|tls| !tls.client_ca_certs().is_empty())
  }
}

/// A router that encapsulates hostname-based routing logic.
///
/// Wraps a list of `Server` entries and provides efficient routing
/// by hostname, supporting exact matches, wildcard matches, and
/// default fallback.
#[derive(Clone)]
pub(crate) struct ServerRouter {
  routes: Rc<Routes>,
}

struct Routes {
  exact: std::collections::HashMap<String, Rc<Server>>,
  wildcards: std::collections::HashMap<String, Rc<Server>>,
  default: Option<Rc<Server>>,
}

impl ServerRouter {
  pub(crate) fn build(servers: Vec<Server>) -> Self {
    let mut routes = Routes {
      exact: Default::default(),
      wildcards: Default::default(),
      default: None,
    };
    for server in servers {
      let server = Rc::new(server);
      if server.hostnames.is_empty() {
        routes.default.get_or_insert(server.clone());
      }
      for pattern in &server.hostnames {
        let normalized = crate::hostname::normalize(pattern);
        if let Some(suffix) = normalized.strip_prefix("*.") {
          routes
            .wildcards
            .entry(suffix.to_owned())
            .or_insert_with(|| server.clone());
        } else {
          routes
            .exact
            .entry(normalized)
            .or_insert_with(|| server.clone());
        }
      }
    }
    Self { routes: Rc::new(routes) }
  }

  pub(crate) fn route(
    &self,
    hostname: Option<&str>,
  ) -> Option<Rc<Server>> {
    let Some(hostname) = hostname else {
      return self.routes.default.clone();
    };
    let hostname = crate::hostname::normalize(hostname);
    self
      .routes
      .exact
      .get(&hostname)
      .or_else(|| {
        crate::hostname::wildcard_suffix(&hostname)
          .and_then(|suffix| self.routes.wildcards.get(suffix))
      })
      .cloned()
      .or_else(|| self.routes.default.clone())
  }
}
