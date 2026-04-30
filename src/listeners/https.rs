//! HTTPS listener implementation.
//!
//! This listener handles HTTPS (HTTP/1.1 over TLS) connections.
//! TLS configuration is provided at the server level via routing table.

#![allow(clippy::await_holding_refcell_ref)]

use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use hyper::{body as hyper_body, service as hyper_svc};
use hyper_util::rt as rt_util;
use hyper_util::server::conn::auto as conn_util;
use serde::Deserialize;
use tokio::{net, task, time::timeout};
use tower::util as tower_util;
use tracing::{error, info, warn};

use crate::http_utils::{
  BytesBufBodyWrapper, Request, RequestBody, Response,
};
use crate::listeners::common::TokioLocalExecutor;
use crate::plugin;
use crate::server::{Server, ServerRouter};
use crate::shutdown::StreamTracker;
use crate::tls::build_tls_server_config;

/// Listener shutdown timeout in seconds.
const LISTENER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

/// Monitoring log interval in seconds.
const MONITORING_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// HTTPS Listener configuration arguments.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct HttpsListenerArgs {
  /// Listening addresses
  pub addresses: Vec<String>,
}

/// Load TLS server configuration from server routing table.
///
/// This function builds a TLS config that includes certificates from all servers
/// in the routing table, enabling SNI-based certificate selection.
fn load_tls_config_from_servers(
  servers: &[Server],
) -> Result<Arc<rustls::ServerConfig>> {
  // Use HTTP/1.1 ALPN
  build_tls_server_config(servers, vec![b"http/1.1".to_vec()])
}

/// HTTPS Service Adaptor with routing support.
struct HttpsServiceAdaptor {
  /// Server router for hostname-based routing
  server_router: ServerRouter,
  /// Client address for logging
  client_addr: Option<SocketAddr>,
  /// SNI from TLS handshake
  sni: Option<String>,
}

impl HttpsServiceAdaptor {
  fn new(
    server_routing_table: Vec<Server>,
    client_addr: Option<SocketAddr>,
    sni: Option<String>,
  ) -> Self {
    let server_router =
      ServerRouter::build(server_routing_table);
    Self { server_router, client_addr, sni }
  }

  /// Route a request to the correct service based on Host header.
  fn route_request(
    &self,
    req: &Request,
  ) -> Option<std::rc::Rc<Server>> {
    // Get Host header and strip port if present
    let host = req
      .headers()
      .get(http::header::HOST)
      .and_then(|h| h.to_str().ok())
      .map(|h| h.split(':').next().unwrap_or(h));

    self.server_router.route(host)
  }
}

impl hyper_svc::Service<hyper::Request<hyper_body::Incoming>>
  for HttpsServiceAdaptor
{
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
  type Response = Response;

  fn call(
    &self,
    req: http::Request<hyper_body::Incoming>,
  ) -> Self::Future {
    let start_time = std::time::Instant::now();

    // Step 1: Check HTTP version FIRST
    // HTTP/1.0 is not supported - return 505 HTTP Version Not Supported
    if let Err(_status) = super::common::check_http_version(req.version()) {
      return Box::pin(async { Ok(super::common::build_505_response()) });
    }

    // Step 2: Check SNI vs Host header mismatch
    // SNI and Host must match per RFC 7540 Section 9.1.2
    if let Some(ref sni) = self.sni {
      if let Some(host) = req.headers().get(http::header::HOST) {
        if let Ok(host_str) = host.to_str() {
          if !super::common::sni_matches_host(sni, host_str) {
            return Box::pin(async {
              Ok(super::common::build_421_misdirected_response())
            });
          }
        }
      }
    }

    // Step 3: Build an http::Request<()> for routing and auth verification
    let mut auth_req_builder = http::Request::builder()
      .method(req.method().clone())
      .uri(req.uri().clone())
      .version(req.version());

    for (name, value) in req.headers() {
      auth_req_builder = auth_req_builder.header(name, value);
    }

    let auth_req = auth_req_builder.body(()).unwrap();

    // Step 4: Route FIRST (route first, then auth)
    let (parts, body) = req.into_parts();
    let req = Request::from_parts(
      parts,
      RequestBody::new(BytesBufBodyWrapper::new(body)),
    );

    let routing_entry = match self.route_request(&req) {
      Some(entry) => entry,
      None => {
        // No matching server found - return 404
        return Box::pin(async {
          Ok(super::common::build_404_response())
        });
      }
    };

    // Step 5: Check authentication using routing_entry's users
    let user_password_auth = super::common::build_user_password_auth(&routing_entry.users);
    let verify_result =
      user_password_auth.verify_and_extract_username(&auth_req);
    let (user, auth_type) = match verify_result {
      Ok(Some(username)) => {
        (Some(username), crate::access_log::AuthType::Password)
      }
      Ok(None) => (None, crate::access_log::AuthType::None),
      Err(_) => {
        return Box::pin(async {
          Ok(super::common::build_407_response())
        });
      }
    };

    // Step 6: Get access_log_writer from routing entry
    let access_log_writer = routing_entry.access_log_writer.clone();
    let service_name = routing_entry.service_name();
    let client_addr = self.client_addr;
    let method = req.method().to_string();
    let target = req.uri().to_string();

    let s = routing_entry.service.clone();
    Box::pin(async move {
      let resp = tower_util::Oneshot::new(s, req).await;

      // Record access log
      if let Some(ref writer) = access_log_writer {
        let duration = start_time.elapsed();
        let status = match &resp {
          Ok(r) => r.status().as_u16(),
          Err(_) => 500,
        };

        let addr =
          client_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let service_metrics = resp
          .as_ref()
          .ok()
          .and_then(|r| {
            r.extensions()
              .get::<crate::access_log::ServiceMetrics>()
              .cloned()
          })
          .unwrap_or_default();

        let params = crate::access_log::HttpAccessLogParams {
          client_addr: addr,
          user,
          auth_type,
          method,
          target,
          status,
          duration,
          service_name,
          service_metrics,
        };

        super::common::record_http_access_log(writer, &params);
      }

      resp
    })
  }
}

/// Extract SNI from TLS connection.
///
/// Returns None if SNI is not available (should not happen for valid HTTPS connections).
/// The SNI (Server Name Indication) is extracted from the TLS handshake.
fn get_sni_from_tls_connection(
  conn: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
  let (_, session) = conn.get_ref();
  session.server_name().map(|s| s.to_string())
}

/// HTTPS Listener with shared-address routing support.
pub struct HttpsListener {
  /// Listening addresses
  addresses: Vec<SocketAddr>,
  /// TLS configuration
  tls_config: Arc<rustls::ServerConfig>,
  /// Routing table for hostname-based routing
  server_routing_table: Vec<Server>,
  /// Listening set for managing accept tasks
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  /// Connection tracker for graceful shutdown
  connection_tracker: Rc<StreamTracker>,
  /// Graceful shutdown timeout
  graceful_shutdown_timeout: Duration,
}

impl HttpsListener {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    sargs: plugin::SerializedArgs,
    server_routing_table: Vec<Server>,
  ) -> Result<plugin::Listener> {
    let args: HttpsListenerArgs = serde_yaml::from_value(sargs)?;

    // TLS config is required for https listener
    // Check that at least one server has TLS configured
    let has_tls = server_routing_table.iter().any(|e| e.tls.is_some());
    if !has_tls {
      bail!("https listener requires server-level tls configuration");
    }

    // Build TLS config from all servers' certificates (SNI-based selection)
    let tls_config = load_tls_config_from_servers(&server_routing_table)?;

    // Parse addresses
    let addresses: Vec<SocketAddr> = args
      .addresses
      .iter()
      .filter_map(|s| {
        s.parse()
          .inspect_err(|e| warn!("address '{}' invalid: {}", s, e))
          .ok()
      })
      .collect();

    Ok(plugin::Listener::new(Self {
      addresses,
      tls_config,
      server_routing_table,
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      connection_tracker: Rc::new(StreamTracker::new()),
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
    }))
  }

  fn serve_addr(
    &self,
    addr: SocketAddr,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>> {
    let socket = match addr {
      std::net::SocketAddr::V4(_) => net::TcpSocket::new_v4()?,
      std::net::SocketAddr::V6(_) => net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;

    let tls_config = self.tls_config.clone();
    let connection_tracker = self.connection_tracker.clone();
    let shutdown_handle = self.connection_tracker.shutdown_handle();
    let server_routing_table = self.server_routing_table.clone();

    let accepting_fut = async move {
      info!("HTTPS listener started on {}", addr);

      let mut monitoring_interval =
        tokio::time::interval(MONITORING_LOG_INTERVAL);
      monitoring_interval.tick().await;

      let shutdown = async move || shutdown_handle.notified().await;
      let accepting = || async {
        match listener.accept().await {
          Err(e) => {
            error!("accepting new connection failed: {}", e);
          }
          Ok((stream, raddr)) => {
            let tls_acceptor =
              tokio_rustls::TlsAcceptor::from(tls_config.clone());
            let io = rt_util::TokioIo::new(stream);

            match tls_acceptor.accept(io.into_inner()).await {
              Ok(tls_stream) => {
                // Extract SNI from TLS connection
                let sni = get_sni_from_tls_connection(&tls_stream);

                let io = rt_util::TokioIo::new(tls_stream);
                let svc = HttpsServiceAdaptor::new(
                  server_routing_table.clone(),
                  Some(raddr),
                  sni,
                );
                let builder =
                  conn_util::Builder::new(TokioLocalExecutor);
                connection_tracker.register(async move {
                  let conn =
                    builder.serve_connection_with_upgrades(io, svc);
                  if let Err(e) = conn.await {
                    error!("HTTPS connection error: {}", e);
                  }
                });
              }
              Err(e) => {
                warn!("TLS handshake failed from {}: {}", raddr, e);
              }
            }
          }
        }
      };

      loop {
        tokio::select! {
            _ = accepting() => {},
            _ = monitoring_interval.tick() => {
                info!(
                    "[https.listener] active_connections={}",
                    connection_tracker.active_count()
                );
            }
            _ = shutdown() => {
                info!("HTTPS listener on {} shutting down", addr);
                break;
            },
        }
      }

      Ok(())
    };

    Ok(Box::pin(accepting_fut))
  }
}

impl plugin::Listening for HttpsListener {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    let listening_set = self.listening_set.clone();
    for addr in &self.addresses {
      let addr = *addr;
      let serve_addr_fut = match self.serve_addr(addr) {
        Err(e) => return Box::pin(std::future::ready(Err(e))),
        Ok(f) => f,
      };
      listening_set.borrow_mut().spawn_local(serve_addr_fut);
    }

    let connection_tracker = self.connection_tracker.clone();
    let shutdown = self.connection_tracker.shutdown_handle();
    let graceful_timeout = self.graceful_shutdown_timeout;

    Box::pin(async move {
      shutdown.notified().await;

      while let Some(res) = listening_set.borrow_mut().join_next().await
      {
        match res {
          Err(e) => error!("listening join error: {}", e),
          Ok(res) => {
            if let Err(e) = res {
              error!("listening error: {}", e);
            }
          }
        }
      }

      let wait_result = timeout(graceful_timeout, async {
        connection_tracker.wait_shutdown().await;
      })
      .await;

      if wait_result.is_err() {
        warn!(
          "graceful shutdown timeout ({:?}) expired, aborting {} remaining connections",
          graceful_timeout,
          connection_tracker.active_count()
        );
        connection_tracker.abort_all();
      }

      Ok(())
    })
  }

  fn stop(&self) {
    self.connection_tracker.shutdown();
  }
}

/// Get the listener name
pub fn listener_name() -> &'static str {
  "https"
}

/// Create a listener builder
pub fn create_listener_builder() -> Box<dyn plugin::BuildListener> {
  Box::new(HttpsListener::new)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{CertificateConfig, ServerTlsConfig};
  use crate::listeners::common::{
    TokioLocalExecutor, build_505_response, check_http_version,
  };
  use std::sync::OnceLock;

  static CRYPTO_PROVIDER_INSTALLED: OnceLock<bool> = OnceLock::new();

  /// Ensure the rustls crypto provider is installed for tests.
  fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
      let _ =
        rustls::crypto::ring::default_provider().install_default();
      true
    });
  }

  /// Generate a test certificate and key pair using rcgen.
  fn generate_test_cert() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![
      "test.local".to_string(),
      "127.0.0.1".to_string(),
    ])
    .unwrap();
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages =
      vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
      .distinguished_name
      .push(rcgen::DnType::CommonName, "test.local");

    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem, key_pem)
  }

  /// Write test certificate and key to temp files.
  fn write_test_cert_files() -> (String, String, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = generate_test_cert();

    let cert_path = temp_dir.path().join("test_cert.pem");
    let key_path = temp_dir.path().join("test_key.pem");

    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    (
      cert_path.to_str().unwrap().to_string(),
      key_path.to_str().unwrap().to_string(),
      temp_dir,
    )
  }

  #[test]
  fn test_https_listener_args_deserialize() {
    let yaml = r#"
addresses:
  - "127.0.0.1:8443"
"#;
    let args: HttpsListenerArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.addresses.len(), 1);
    assert_eq!(args.addresses[0], "127.0.0.1:8443");
  }

  #[test]
  fn test_https_listener_args_default() {
    let args = HttpsListenerArgs::default();
    assert!(args.addresses.is_empty());
  }

  #[test]
  fn test_listener_name() {
    assert_eq!(listener_name(), "https");
  }

  #[test]
  fn test_listening_trait_implementation() {
    fn assert_listening<T: plugin::Listening>() {}
    assert_listening::<HttpsListener>();
  }

  #[test]
  fn test_https_listener_requires_tls_in_context() {
    ensure_crypto_provider();
    // HTTPS listener should fail to build if no TLS in routing table
    let args_yaml = r#"
addresses:
  - "127.0.0.1:8443"
"#;
    let args: plugin::SerializedArgs =
      serde_yaml::from_str(args_yaml).unwrap();

    let entry = Server {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: "test_service".to_string(),
      users: None,
      tls: None, // No TLS config - should cause error
      access_log_writer: None,
    };

    // This should return an error because tls is required for https
    let result = HttpsListener::new(args, vec![entry]);
    assert!(
      result.is_err(),
      "HTTPS listener should fail without TLS config"
    );
    assert!(
      result.err().unwrap().to_string().contains(
        "https listener requires server-level tls configuration"
      ),
      "Error message should mention TLS requirement"
    );
  }

  #[test]
  fn test_create_listener_builder() {
    let _builder = create_listener_builder();
  }

  #[test]
  fn test_graceful_shutdown_timeout_is_3_seconds() {
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT.as_secs(), 3);
    assert_eq!(LISTENER_SHUTDOWN_TIMEOUT.as_millis(), 3000);
  }

  #[test]
  fn test_monitoring_log_interval_is_60_seconds() {
    assert_eq!(MONITORING_LOG_INTERVAL.as_secs(), 60);
    assert_eq!(MONITORING_LOG_INTERVAL.as_millis(), 60000);
  }

  #[test]
  fn test_tokio_local_executor() {
    let executor = TokioLocalExecutor;
    let _cloned = executor.clone();
  }

  // ============== load_tls_config_from_servers Tests ==============

  #[test]
  fn test_load_tls_config_from_servers_valid_cert() {
    ensure_crypto_provider();
    let (cert_path, key_path, _temp_dir) = write_test_cert_files();

    let entry = Server {
      hostnames: vec!["test.local".to_string()],
      service: crate::server::placeholder_service(),
      service_name: "test_service".to_string(),
      users: None,
      tls: Some(ServerTlsConfig {
        certificates: vec![CertificateConfig { cert_path, key_path }],
        client_ca_certs: None,
      }),
      access_log_writer: None,
    };

    let result = load_tls_config_from_servers(&[entry]);
    assert!(result.is_ok(), "Should load valid TLS config");
  }

  #[test]
  fn test_load_tls_config_from_servers_empty_certificates() {
    ensure_crypto_provider();

    let entry = Server {
      hostnames: vec![],
      service: crate::server::placeholder_service(),
      service_name: "test_service".to_string(),
      users: None,
      tls: Some(ServerTlsConfig {
        certificates: vec![],
        client_ca_certs: None,
      }),
      access_log_writer: None,
    };

    // Should succeed but resolver will have no certificates
    let result = load_tls_config_from_servers(&[entry]);
    assert!(result.is_ok(), "Should succeed with empty certificates list");
  }

  #[test]
  fn test_load_tls_config_from_servers_multiple_servers() {
    ensure_crypto_provider();
    let (cert_path1, key_path1, _temp_dir1) = write_test_cert_files();
    let (cert_path2, key_path2, _temp_dir2) = write_test_cert_files();

    let entries = vec![
      Server {
        hostnames: vec!["app1.test.local".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "server1".to_string(),
        users: None,
        tls: Some(ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: cert_path1,
            key_path: key_path1,
          }],
          client_ca_certs: None,
        }),
        access_log_writer: None,
      },
      Server {
        hostnames: vec!["app2.test.local".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "server2".to_string(),
        users: None,
        tls: Some(ServerTlsConfig {
          certificates: vec![CertificateConfig {
            cert_path: cert_path2,
            key_path: key_path2,
          }],
          client_ca_certs: None,
        }),
        access_log_writer: None,
      },
    ];

    let result = load_tls_config_from_servers(&entries);
    assert!(
      result.is_ok(),
      "Should load TLS config from multiple servers"
    );
  }

  // ============== HTTP Version Check Tests ==============

  #[test]
  fn test_check_http_version_http10_returns_505() {
    let version = http::Version::HTTP_10;
    let result = check_http_version(version);
    assert!(result.is_err());
    assert_eq!(
      result.unwrap_err(),
      http::StatusCode::HTTP_VERSION_NOT_SUPPORTED
    );
  }

  #[test]
  fn test_check_http_version_http11_ok() {
    let version = http::Version::HTTP_11;
    let result = check_http_version(version);
    assert!(result.is_ok());
  }

  #[test]
  fn test_check_http_version_http2_ok() {
    let version = http::Version::HTTP_2;
    let result = check_http_version(version);
    assert!(result.is_ok());
  }

  #[test]
  fn test_build_505_response() {
    let resp = build_505_response();
    assert_eq!(
      resp.status(),
      http::StatusCode::HTTP_VERSION_NOT_SUPPORTED
    );
    assert!(resp.headers().get(http::header::CONTENT_TYPE).is_some());
  }

  // ============== Task 009: ServerRouter Routing Behavior Tests ==============

  #[test]
  fn test_https_listener_routes_by_hostname() {
    // Verify that HttpsServiceAdaptor correctly routes requests to the
    // right server based on the Host header via ServerRouter.
    let servers = vec![
      Server {
        hostnames: vec![],
        service: crate::server::placeholder_service(),
        service_name: "default".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
      Server {
        hostnames: vec!["api.example.com".to_string()],
        service: crate::server::placeholder_service(),
        service_name: "api".to_string(),
        users: None,
        tls: None,
        access_log_writer: None,
      },
    ];

    let adaptor = HttpsServiceAdaptor::new(servers, None, None);

    // Request with Host header matching api.example.com
    let req_api = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "api.example.com")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    let result = adaptor.route_request(&req_api);
    assert!(result.is_some());
    assert_eq!(
      result.unwrap().service_name,
      "api",
      "Request with Host: api.example.com should route to api server"
    );

    // Request with Host header not matching any specific server
    let req_other = http::Request::builder()
      .method("GET")
      .uri("/test")
      .header(http::header::HOST, "other.example.com")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    let result = adaptor.route_request(&req_other);
    assert!(result.is_some());
    assert_eq!(
      result.unwrap().service_name,
      "default",
      "Request with non-matching Host should route to default server"
    );

    // Request without Host header
    let req_no_host = http::Request::builder()
      .method("GET")
      .uri("/test")
      .body(RequestBody::new(BytesBufBodyWrapper::new(
        http_body_util::Empty::new(),
      )))
      .unwrap();

    let result = adaptor.route_request(&req_no_host);
    assert!(result.is_some());
    assert_eq!(
      result.unwrap().service_name,
      "default",
      "Request without Host header should route to default server"
    );
  }
}
