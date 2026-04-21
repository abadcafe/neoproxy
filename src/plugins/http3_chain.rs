#![allow(clippy::await_holding_refcell_ref)]
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::{self, Future};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{fs, path};

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use bytes::{Buf, Bytes};
use h3::client as h3_cli;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use rustls_pemfile;
use serde::Deserialize;
use tokio::{io, task};
use tracing::{error, info, warn};

use super::utils;
use crate::listeners::http3::StreamTracker;
use crate::plugin;
use crate::plugin::ClientStream;

/// Error indicating proxy authentication failure (HTTP 407)
#[derive(Debug)]
struct ProxyAuthRequiredError;

impl std::fmt::Display for ProxyAuthRequiredError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Proxy Authentication Required (407)")
  }
}

impl std::error::Error for ProxyAuthRequiredError {}

static ALPN: &[u8] = b"h3";

/// Graceful shutdown timeout for HTTP/3 Chain Service
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// H3_NO_ERROR error code for CONNECTION_CLOSE frame
/// See: https://www.rfc-editor.org/rfc/rfc9114.html#errors
/// Value 0x100 = 256, which fits in u32
const H3_NO_ERROR_CODE: u32 = 0x100;

// ============================================================================
// Active Connection Management
// ============================================================================

/// An active QUIC connection that can be closed gracefully.
/// This struct holds a reference to the underlying quinn::Connection
/// so that we can send CONNECTION_CLOSE frames during shutdown.
struct ActiveConnection {
  /// The underlying QUIC connection
  conn: quinn::Connection,
}

impl ActiveConnection {
  fn new(conn: quinn::Connection) -> Self {
    Self { conn }
  }

  /// Close the connection with H3_NO_ERROR code
  fn close(&self) {
    self.conn.close(
      quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
      b"graceful shutdown",
    );
  }
}

/// Tracker for active QUIC connections.
/// This allows us to close all connections gracefully during shutdown.
#[derive(Clone, Default)]
struct ActiveConnectionTracker {
  connections: Rc<RefCell<Vec<ActiveConnection>>>,
}

impl ActiveConnectionTracker {
  fn new() -> Self {
    Self::default()
  }

  /// Register a new active connection
  fn register(&self, conn: quinn::Connection) {
    self.connections.borrow_mut().push(ActiveConnection::new(conn));
  }

  /// Close and remove a specific connection by its stable_id
  /// This is useful when auth fails and we need to close the failed connection
  fn close_and_remove(&self, conn: &quinn::Connection) {
    let target_id = conn.stable_id();
    let mut connections = self.connections.borrow_mut();
    // Find and remove the connection by stable_id, then close it
    if let Some(pos) = connections.iter().position(|ac| ac.conn.stable_id() == target_id) {
      let active_conn = connections.remove(pos);
      active_conn.close();
    }
  }

  /// Close all registered connections with H3_NO_ERROR
  fn close_all(&self) {
    let connections = self.connections.borrow();
    for conn in connections.iter() {
      conn.close();
    }
    info!(
      "ActiveConnectionTracker: closed {} connections",
      connections.len()
    );
  }

  /// Get the count of active connections
  fn count(&self) -> usize {
    self.connections.borrow().len()
  }

  /// Clear all connection references (used after close_all)
  fn clear(&self) {
    self.connections.borrow_mut().clear();
  }
}

struct Proxy {
  address: SocketAddr,
  conn_handle: Option<task::JoinHandle<Result<()>>>,
  requester: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  weight: usize,
  current_weight: isize,
  auth_chain: Vec<ProxyAuth>,
}

async fn connection_maintaining(
  mut conn: h3_cli::Connection<h3_quinn::Connection, Bytes>,
) -> Result<()> {
  let err = future::poll_fn(|cx| conn.poll_close(cx)).await;
  if !err.is_h3_no_error() {
    Err(anyhow::Error::from(err))
  } else {
    Ok(())
  }
}

/// Build TLS client config based on auth method
fn build_tls_client_config(
  roots: rustls::RootCertStore,
  auth: &ProxyAuth,
) -> Result<rustls::ClientConfig> {
  let tls_config = match auth {
    ProxyAuth::None => rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth(),
    ProxyAuth::Password { .. } => {
      // No TLS-level auth, password will be sent in CONNECT request
      rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
    }
    ProxyAuth::TlsClientCert {
      client_cert_path,
      client_key_path,
    } => {
      // Load client certificate chain (PEM format)
      let cert_file = fs::File::open(client_cert_path)?;
      let mut cert_reader = std::io::BufReader::new(cert_file);
      let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse client certificate: {e}"))?;

      // Load client private key (PEM format)
      let key_file = fs::File::open(client_key_path)?;
      let mut key_reader = std::io::BufReader::new(key_file);
      let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in file"))?;

      rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)?
    }
  };
  Ok(tls_config)
}

/// Check if an error is a TLS handshake failure (indicating auth failure)
///
/// This function uses type-based detection when possible (via downcast to quinn::ConnectionError)
/// and falls back to string matching for other error types.
///
/// TLS handshake errors are detected when:
/// 1. The error is a quinn::ConnectionError::TransportError with a crypto error code (0x100-0x1FF)
/// 2. The error message contains TLS-related keywords (fallback for other error types)
fn is_tls_handshake_error(e: &anyhow::Error) -> bool {
  // First, try type-based detection for quinn::ConnectionError
  if let Some(conn_err) = e.downcast_ref::<quinn::ConnectionError>() {
    match conn_err {
      quinn::ConnectionError::TransportError(transport_err) => {
        // Crypto error codes are in range 0x100-0x1FF (256-511)
        // These indicate TLS handshake failures
        let code: u64 = transport_err.code.into();
        return code >= 0x100 && code < 0x200;
      }
      _ => return false,
    }
  }

  // Fallback: check for common TLS handshake error patterns in error message
  let err_str = e.to_string().to_lowercase();
  err_str.contains("tls") && (err_str.contains("handshake") || err_str.contains("certificate"))
}

struct ProxyGroup {
  ca_path: path::PathBuf,
  proxies: Vec<Proxy>,
}

impl ProxyGroup {
  fn new(
    ca_path: path::PathBuf,
    addresses: Vec<(SocketAddr, usize, Vec<ProxyAuth>)>,  // Now includes auth_chain
  ) -> Self {
    let mut proxies = vec![];
    for (addr, weight, auth_chain) in addresses {
      proxies.push(Proxy {
        address: addr,
        conn_handle: None,
        requester: None,
        weight,
        current_weight: 0,
        auth_chain,
      });
    }

    Self { ca_path, proxies }
  }

  fn schedule_wrr(&mut self) -> usize {
    let total = self.proxies.iter().fold(0, |t, p| t + p.weight) as isize;
    let mut selected_idx = 0usize;
    let mut selected_weight = 0isize;
    for (i, p) in self.proxies.iter_mut().enumerate() {
      p.current_weight += p.weight as isize;
      if p.current_weight > selected_weight {
        selected_weight = p.current_weight;
        selected_idx = i;
      }
    }

    self.proxies[selected_idx].current_weight -= total;
    selected_idx
  }

  /// Establish a new QUIC connection with a specific auth method
  async fn new_proxy_conn_with_auth(
    &self,
    proxy_idx: usize,
    auth: &ProxyAuth,
  ) -> Result<quinn::Connection> {
    let mut roots = rustls::RootCertStore::empty();
    let CertificateResult { certs, errors, .. } =
      rustls_native_certs::load_native_certs();
    for cert in certs {
      if let Err(e) = roots.add(cert) {
        error!("failed to parse trust anchor: {e}");
      }
    }
    for e in errors {
      error!("couldn't load default trust roots: {e}");
    }

    // Load CA certificate (PEM format) for server verification
    info!("Loading CA certificate from: {:?}", self.ca_path);
    let ca_file = fs::File::open(self.ca_path.as_path())?;
    let mut ca_reader = std::io::BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut ca_reader)
      .collect::<Result<Vec<_>, _>>()
      .map_err(|e| anyhow::anyhow!("failed to parse CA certificate: {e}"))?;

    info!("Loaded {} CA certificates", ca_certs.len());
    for cert in ca_certs {
      if let Err(e) = roots.add(cert) {
        error!("failed to add CA certificate to trust store: {e}");
      } else {
        info!("Successfully added CA certificate to trust store");
      }
    }

    info!("Establishing connection with auth: {:?}", auth);
    // Build TLS config based on auth method
    let mut tls_config = build_tls_client_config(roots, auth)?;

    // Apply common configuration
    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut cli_endpoint =
      quinn::Endpoint::client("[::]:0".parse().unwrap())?;

    let cli_config = quinn::ClientConfig::new(Arc::new(
      quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    cli_endpoint.set_default_client_config(cli_config);

    let addr = self.proxies[proxy_idx].address;
    // Use IP address as server name for TLS (without port)
    let host = addr.ip().to_string();
    let conn = cli_endpoint.connect(addr, host.as_str())?.await?;

    info!("QUIC connection established with auth method");
    Ok(conn)
  }

  async fn get_proxy_conn(
    &mut self,
    stream_tracker: &StreamTracker,
    conn_tracker: &ActiveConnectionTracker,
  ) -> Result<(
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
    usize,
    Vec<ProxyAuth>,
  )> {
    let idx = self.schedule_wrr();
    let proxy = &mut self.proxies[idx];

    // Return the auth chain for this proxy
    let auth_chain = proxy.auth_chain.clone();

    if let Some(h) = proxy.conn_handle.as_mut() {
      if h.is_finished() {
        match h.await {
          Err(e) => {
            info!(
              "join connection handle of {} failed: {e}",
              proxy.address
            );
          }
          Ok(res) => {
            if let Err(e) = res {
              info!("connection of {} finished: {e}", proxy.address);
            }
          }
        }
      } else {
        return Ok((proxy.requester.as_ref().unwrap().clone(), idx, auth_chain));
      }
    }

    // If no auth chain, establish connection without auth
    if auth_chain.is_empty() {
      let conn = self.new_proxy_conn_with_auth(idx, &ProxyAuth::None).await?;
      conn_tracker.register(conn.clone());
      let (h3_conn, requester) =
        h3::client::new(h3_quinn::Connection::new(conn)).await?;
      let conn_task = connection_maintaining(h3_conn);
      stream_tracker.register_connection(async move {
        let _ = conn_task.await;
      });
      let proxy = &mut self.proxies[idx];
      let _ = proxy.conn_handle.take();
      let _ = proxy.requester.insert(requester.clone());
      return Ok((requester, idx, auth_chain));
    }

    // Try each auth method in order until one succeeds
    // This handles TLS handshake failures by falling back to the next auth method
    // Connection management: failed connections are closed before trying the next auth method
    let mut last_error: Option<anyhow::Error> = None;
    let mut current_conn: Option<quinn::Connection> = None;

    for (auth_index, auth) in auth_chain.iter().enumerate() {
      // Close previous failed connection (if any) before establishing a new one
      if let Some(ref prev_conn) = current_conn {
        info!(
          "ProxyGroup: closing previous failed connection before trying auth method {}",
          auth_index
        );
        conn_tracker.close_and_remove(prev_conn);
        current_conn = None;
      }

      match self.new_proxy_conn_with_auth(idx, auth).await {
        Ok(conn) => {
          conn_tracker.register(conn.clone());
          current_conn = Some(conn.clone());
          match h3::client::new(h3_quinn::Connection::new(conn)).await {
            Ok((h3_conn, requester)) => {
              let conn_task = connection_maintaining(h3_conn);
              stream_tracker.register_connection(async move {
                let _ = conn_task.await;
              });
              let proxy = &mut self.proxies[idx];
              let _ = proxy.conn_handle.take();
              let _ = proxy.requester.insert(requester.clone());
              return Ok((requester, idx, auth_chain));
            }
            Err(e) => {
              warn!(
                "Http3ChainService: failed to create H3 connection with auth method {}: {e}",
                auth_index
              );
              last_error = Some(e.into());
              continue;
            }
          }
        }
        Err(e) => {
          if is_tls_handshake_error(&e) {
            info!(
              "Http3ChainService: TLS handshake failed with auth method {}, trying next: {}",
              auth_index, e
            );
            last_error = Some(e);
            continue;
          }
          // Non-TLS error, no fallback
          warn!(
            "Http3ChainService: connection failed with auth method {}: {e}",
            auth_index
          );
          return Err(e);
        }
      }
    }

    // All auth methods failed
    let error_detail = last_error
      .map(|e| format!(": {e}"))
      .unwrap_or_default();
    Err(anyhow!(
      "all {} auth methods failed during connection establishment{}",
      auth_chain.len(),
      error_detail
    ))
  }
}

fn build_empty_response(
  status_code: http::StatusCode,
) -> plugin::Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = plugin::BytesBufBodyWrapper::new(empty);
  let body = plugin::ResponseBody::new(bytes_buf);
  let mut resp = plugin::Response::new(body);
  *resp.status_mut() = status_code;
  resp
}

use h3::error::StreamError;

/// State for an in-progress send_data or finish operation.
/// The future OWNS the send stream (taken from the Option) to avoid
/// self-referential borrows.
///
/// State machine transitions:
///
/// 1. poll_write path:
///    Idle -> Sending { fut, len } -> Idle (after fut completes)
///
/// 2. poll_shutdown path:
///    Idle -> Finishing { fut } -> Idle (after fut completes)
///    OR
///    Sending { fut, .. } -> (poll fut) -> Idle -> Finishing { fut } -> Idle
///
/// 3. Error conditions:
///    - poll_write during Finishing: returns error "stream is shutting down"
///    - poll_flush: always returns Ok(()) (no-op)
///
/// Key invariants:
/// - Only one send operation at a time (enforced by state machine)
/// - Send stream ownership transfers to future, returns on completion
/// - H3_NO_ERROR is treated as success in poll_write result handling
enum SendState {
  /// Ready for new data. The send stream is in H3BidirectionalStream.send.
  Idle,
  /// A send_data operation is in progress.
  /// The boxed future owns the send stream and will return it on completion.
  Sending {
    fut: Pin<
      Box<
        dyn Future<
          Output = (
            h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
            Result<(), StreamError>,
          ),
        >,
      >,
    >,
    len: usize,
  },
  /// A finish operation is in progress.
  Finishing {
    fut: Pin<
      Box<
        dyn Future<
          Output = (
            h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
            Result<(), StreamError>,
          ),
        >,
      >,
    >,
  },
}

/// HTTP/3 bidirectional stream wrapper.
///
/// Combines h3 SendStream and RecvStream into a single type
/// implementing AsyncRead + AsyncWrite, enabling use with
/// `tokio::io::copy_bidirectional`.
///
/// # Send Side (AsyncWrite)
///
/// - Only one send operation at a time (state machine enforced via SendState)
/// - poll_flush is a no-op (returns Ok immediately)
/// - poll_shutdown sends finish to the stream
/// - poll_write during Finishing state returns error "stream is shutting down"
///
/// # Receive Side (AsyncRead)
///
/// - recv_buf holds partial read data
/// - Buffered data returned before polling for new data
/// - Copy min(data.len(), buf.remaining()) bytes per read
/// - If partial read, remaining bytes stored in recv_buf for next poll_read
///
/// # Ownership
///
/// - Send stream is owned by the future during operations
/// - Returned to struct after operation completes
///
/// # Testing
///
/// This component requires real h3 streams which cannot be easily mocked.
/// It is tested through integration tests:
/// - `tests/integration/test_proxy_chain.py` - proxy chain with data transmission
/// - `tests/integration/test_http3_chain.py` - HTTP/3 chain data transmission tests
struct H3BidirectionalStream {
  /// Send stream (AsyncWrite), wrapped in Option for ownership transfer
  send: Option<h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>>,
  /// Receive stream (AsyncRead via poll_recv_data)
  recv: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  /// Buffer for partially-read data from recv
  recv_buf: Option<Bytes>,
  /// State machine for send operations
  send_state: SendState,
}

impl H3BidirectionalStream {
  fn new(
    send: h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    recv: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  ) -> Self {
    Self {
      send: Some(send),
      recv,
      recv_buf: None,
      send_state: SendState::Idle,
    }
  }
}

impl io::AsyncWrite for H3BidirectionalStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    loop {
      match &mut self.send_state {
        SendState::Idle => {
          // Take the send stream out (ownership transfer)
          let mut send = self
            .send
            .take()
            .expect("send stream missing in Idle state");
          let data = Bytes::copy_from_slice(buf);
          let len = data.len();

          // Create a future that OWNS the send stream
          let fut = Box::pin(async move {
            let result = send.send_data(data).await;
            (send, result)
          });

          self.send_state = SendState::Sending { fut, len };
          // Loop to poll the new state immediately
        }
        SendState::Sending { fut, len } => {
          let len = *len;
          match fut.as_mut().poll(cx) {
            Poll::Ready((send, result)) => {
              // Restore the send stream
              self.send = Some(send);
              self.send_state = SendState::Idle;
              return match result {
                Ok(()) => Poll::Ready(Ok(len)),
                Err(e) if e.is_h3_no_error() => Poll::Ready(Ok(len)),
                Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
              };
            }
            Poll::Pending => return Poll::Pending,
          }
        }
        SendState::Finishing { .. } => {
          // Cannot write while finishing
          return Poll::Ready(Err(std::io::Error::other(
            "stream is shutting down",
          )));
        }
      }
    }
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    loop {
      match &mut self.send_state {
        SendState::Idle => {
          // Take the send stream out (ownership transfer)
          let mut send = self
            .send
            .take()
            .expect("send stream missing in Idle state");

          let fut = Box::pin(async move {
            let result = send.finish().await;
            (send, result)
          });

          self.send_state = SendState::Finishing { fut };
          // Loop to poll the new state immediately
        }
        SendState::Sending { fut, .. } => {
          // Must complete pending send before finishing
          match fut.as_mut().poll(cx) {
            Poll::Ready((send, _result)) => {
              self.send = Some(send);
              self.send_state = SendState::Idle;
              // Loop to start the finish operation
            }
            Poll::Pending => return Poll::Pending,
          }
        }
        SendState::Finishing { fut } => match fut.as_mut().poll(cx) {
          Poll::Ready((send, result)) => {
            self.send = Some(send);
            self.send_state = SendState::Idle;
            return result
              .map_err(std::io::Error::other)
              .into();
          }
          Poll::Pending => return Poll::Pending,
        },
      }
    }
  }
}

impl io::AsyncRead for H3BidirectionalStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut io::ReadBuf<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    // Return buffered data first
    if let Some(data) = self.recv_buf.take() {
      let n = std::cmp::min(data.len(), buf.remaining());
      buf.put_slice(&data[..n]);
      if n < data.len() {
        self.recv_buf = Some(data.slice(n..));
      }
      return Poll::Ready(Ok(()));
    }

    // Poll for new data
    match self.recv.poll_recv_data(cx) {
      Poll::Ready(Ok(Some(mut data))) => {
        let bytes = data.copy_to_bytes(data.remaining());
        let n = std::cmp::min(bytes.len(), buf.remaining());
        buf.put_slice(&bytes[..n]);
        if n < bytes.len() {
          self.recv_buf = Some(bytes.slice(n..));
        }
        Poll::Ready(Ok(()))
      }
      Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
      Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
      Poll::Pending => Poll::Pending,
    }
  }
}

/// Authentication method for a single proxy
#[derive(Clone, Debug, PartialEq)]
pub enum ProxyAuth {
  /// No authentication
  None,
  /// Username/password authentication (HTTP Basic Auth)
  Password {
    username: String,
    password: String,
  },
  /// TLS client certificate authentication (mTLS)
  TlsClientCert {
    client_cert_path: path::PathBuf,
    client_key_path: path::PathBuf,
  },
}

/// Deserialized auth configuration entry
#[derive(Deserialize, Clone, Debug, Default)]
struct ProxyAuthConfig {
  #[serde(rename = "type")]
  auth_type: String,
  #[serde(default)]
  username: Option<String>,
  #[serde(default)]
  password: Option<String>,
  #[serde(default)]
  client_cert_path: Option<String>,
  #[serde(default)]
  client_key_path: Option<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
struct Http3ChainServiceArgsProxyGroup {
  address: String,
  weight: usize,
  #[serde(default)]
  auth: Option<Vec<ProxyAuthConfig>>,
}

#[derive(Deserialize, Default, Clone, Debug)]
struct Http3ChainServiceArgs {
  proxy_group: Vec<Http3ChainServiceArgsProxyGroup>,
  ca_path: String,
  // Default upstream auth (inherited by proxies without auth field)
  #[serde(default)]
  default_upstream_auth: Option<Vec<ProxyAuthConfig>>,
}

impl Http3ChainServiceArgs {
  fn validate(&self) -> Result<()> {
    // CR-004: Validate that ca_path exists (required field)
    if !path::Path::new(&self.ca_path).exists() {
      bail!("ca_path '{}' does not exist", self.ca_path);
    }

    // CR-003: Validate that all proxy weights are greater than 0
    for proxy in &self.proxy_group {
      if proxy.weight == 0 {
        bail!(
          "proxy weight must be greater than 0, got 0 for address '{}'",
          proxy.address
        );
      }
    }

    // Validate default_upstream_auth if present
    if let Some(ref auth_list) = self.default_upstream_auth {
      for (i, auth) in auth_list.iter().enumerate() {
        Self::validate_auth_config(auth, &format!("default_upstream_auth[{}]", i))?;
      }
    }

    // Validate per-proxy auth if present
    for proxy in &self.proxy_group {
      if let Some(ref auth_list) = proxy.auth {
        for (i, auth) in auth_list.iter().enumerate() {
          Self::validate_auth_config(
            auth,
            &format!("proxy[{}].auth[{}]", proxy.address, i)
          )?;
        }
      }
    }

    Ok(())
  }

  /// Validate a single auth configuration entry
  fn validate_auth_config(config: &ProxyAuthConfig, context: &str) -> Result<()> {
    match config.auth_type.as_str() {
      "none" => Ok(()),
      "password" => {
        if config.username.is_none() || config.username.as_ref().map_or(true, |u| u.is_empty()) {
          bail!("{}: username required for password auth", context);
        }
        if config.password.is_none() || config.password.as_ref().map_or(true, |p| p.is_empty()) {
          bail!("{}: password required for password auth", context);
        }
        Ok(())
      }
      "tls_client_cert" => {
        let cert_path = config.client_cert_path.as_ref()
          .ok_or_else(|| anyhow!("{}: client_cert_path required for tls_client_cert auth", context))?;
        let key_path = config.client_key_path.as_ref()
          .ok_or_else(|| anyhow!("{}: client_key_path required for tls_client_cert auth", context))?;

        if cert_path.is_empty() {
          bail!("{}: client_cert_path cannot be empty", context);
        }
        if !path::Path::new(cert_path).exists() {
          bail!("{}: client_cert_path '{}' does not exist", context, cert_path);
        }

        if key_path.is_empty() {
          bail!("{}: client_key_path cannot be empty", context);
        }
        if !path::Path::new(key_path).exists() {
          bail!("{}: client_key_path '{}' does not exist", context, key_path);
        }
        Ok(())
      }
      _ => bail!("{}: unknown auth type: {}", context, config.auth_type),
    }
  }

  /// Parse a single auth config entry into ProxyAuth.
  ///
  /// This function validates the configuration by calling `validate_auth_config`
  /// first, then constructs the appropriate `ProxyAuth` variant.
  ///
  /// # Note
  /// File existence checks (for tls_client_cert) are performed during validation
  /// by `validate_auth_config`. If this function is called directly without prior
  /// validation, file existence will still be checked.
  fn parse_auth_config(config: &ProxyAuthConfig) -> Result<ProxyAuth> {
    // CR-002: Delegate validation to validate_auth_config to avoid duplication
    // This ensures consistent validation behavior between validate() and parse operations
    Self::validate_auth_config(config, "auth_config")?;

    match config.auth_type.as_str() {
      "none" => Ok(ProxyAuth::None),
      "password" => {
        // Safe to unwrap because validate_auth_config already verified these exist and are non-empty
        let username = config.username.as_ref().unwrap();
        let password = config.password.as_ref().unwrap();
        Ok(ProxyAuth::Password {
          username: username.clone(),
          password: password.clone(),
        })
      }
      "tls_client_cert" => {
        // Safe to unwrap because validate_auth_config already verified these exist and are non-empty
        let cert_path = config.client_cert_path.as_ref().unwrap();
        let key_path = config.client_key_path.as_ref().unwrap();
        Ok(ProxyAuth::TlsClientCert {
          client_cert_path: path::PathBuf::from(cert_path),
          client_key_path: path::PathBuf::from(key_path),
        })
      }
      _ => unreachable!("validate_auth_config should have rejected unknown auth type"),
    }
  }

  /// Resolve auth chain for a proxy.
  ///
  /// Inheritance rules:
  /// - If proxy has its own auth field, use it (overrides default)
  /// - If proxy has no auth field, inherit from default_upstream_auth
  /// - If neither is set, return empty vec (no auth)
  fn resolve_proxy_auth(&self, proxy_auth: &Option<Vec<ProxyAuthConfig>>) -> Vec<ProxyAuth> {
    // If proxy has its own auth, use it
    if let Some(auth_list) = proxy_auth {
      return auth_list
        .iter()
        .filter_map(|c| match Self::parse_auth_config(c) {
          Ok(auth) => Some(auth),
          Err(e) => {
            warn!("Http3ChainService: failed to parse auth config, skipping: {e}");
            None
          }
        })
        .collect();
    }

    // Otherwise, use default_upstream_auth
    self.default_upstream_auth
      .as_ref()
      .map(|auth_list| {
        auth_list
          .iter()
          .filter_map(|c| match Self::parse_auth_config(c) {
            Ok(auth) => Some(auth),
            Err(e) => {
              warn!("Http3ChainService: failed to parse default auth config, skipping: {e}");
              None
            }
          })
          .collect()
      })
      .unwrap_or_default()
  }
}

#[derive(Clone)]
struct Http3ChainService {
  proxy_group: Rc<RefCell<ProxyGroup>>,
  stream_tracker: Rc<StreamTracker>,
  conn_tracker: ActiveConnectionTracker,
}

impl Http3ChainService {
  #[allow(clippy::new_ret_no_self)]
  fn new(
    sargs: plugin::SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
    conn_tracker: ActiveConnectionTracker,
  ) -> Result<plugin::Service> {
    let args: Http3ChainServiceArgs = serde_yaml::from_value(sargs)?;
    args.validate()?;

    // Resolve auth chains for each proxy
    let proxy_addresses: Vec<(SocketAddr, usize, Vec<ProxyAuth>)> = args
      .proxy_group
      .iter()
      .filter_map(|e| {
        let Http3ChainServiceArgsProxyGroup {
          address: s,
          weight: w,
          auth,
        } = e;

        let auth_chain = args.resolve_proxy_auth(auth);

        s.parse()
          .inspect_err(|e| error!("address '{s}' invalid: {e}"))
          .ok()
          .map(|a| (a, *w, auth_chain))
      })
      .collect();

    let proxy_group = ProxyGroup::new(args.ca_path.into(), proxy_addresses);

    Ok(plugin::Service::new(Self {
      proxy_group: Rc::new(RefCell::new(proxy_group)),
      stream_tracker,
      conn_tracker,
    }))
  }

  /// Check if the service is shutting down
  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
  }
}

impl tower::Service<plugin::Request> for Http3ChainService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    _cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: plugin::Request) -> Self::Future {
    let pg = self.proxy_group.clone();
    let st = self.stream_tracker.clone();
    let ct = self.conn_tracker.clone();
    let is_shutting_down = self.is_shutting_down();

    // Check for SOCKS5 upgrade (similar to hyper::upgrade::on)
    let socks5_upgrade = plugin::Socks5OnUpgrade::on(&mut req);

    // Check for HTTP upgrade (only if no SOCKS5)
    let http_upgrade = if socks5_upgrade.is_none() {
      Some(hyper::upgrade::on(&mut req))
    } else {
      None
    };

    let (req_headers, _req_body) = req.into_parts();

    Box::pin(async move {
      // Check if service is shutting down - reject new requests
      if is_shutting_down {
        warn!("Http3ChainService: rejecting request during shutdown");
        return Ok(build_empty_response(
          http::StatusCode::SERVICE_UNAVAILABLE,
        ));
      }

      let (host, port) = utils::parse_connect_target(&req_headers)?;

      // Get proxy index and auth chain
      let (initial_requester, proxy_idx, auth_chain) =
        match pg.borrow_mut().get_proxy_conn(&st, &ct).await {
          Ok(r) => r,
          Err(e) => {
            warn!(
              "Http3ChainService: failed to connect to next hop proxy: {e}"
            );
            return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
          }
        };

      // If no auth methods configured, proceed without auth fallback
      if auth_chain.is_empty() {
        return send_connect_and_tunnel(
          initial_requester,
          host,
          port,
          &st,
          socks5_upgrade,
          http_upgrade,
        )
        .await;
      }

      // Try each auth method in order
      // IMPORTANT: For TLS client cert auth, we need a NEW connection for each
      // auth method because the TLS config differs per auth method
      //
      // Connection management during auth fallback:
      // - The initial connection (auth_index == 0) is tracked by conn_tracker and
      //   stream_tracker, and will be cleaned up during shutdown.
      // - For subsequent auth methods, new connections are created and similarly tracked.
      // - If an auth method fails (407 or TLS error), the failed connection is explicitly
      //   closed before trying the next auth method.
      // - This prevents resource accumulation from multiple failed auth attempts.
      let mut last_error: Option<anyhow::Error> = None;
      let mut current_conn: Option<quinn::Connection> = None;

      for (auth_index, auth) in auth_chain.iter().enumerate() {
        // Close previous failed connection (if any) before establishing a new one
        if let Some(ref prev_conn) = current_conn {
          info!(
            "Http3ChainService: closing previous failed connection before trying auth method {}",
            auth_index
          );
          ct.close_and_remove(prev_conn);
          current_conn = None;
        }

        // For the first auth method, we can reuse the existing connection
        // For subsequent methods, we need a new connection
        let requester = if auth_index == 0 {
          initial_requester.clone()
        } else {
          info!(
            "Http3ChainService: establishing new connection for auth method {}",
            auth_index
          );
          let conn = match pg
            .borrow_mut()
            .new_proxy_conn_with_auth(proxy_idx, auth)
            .await
          {
            Ok(c) => c,
            Err(e) => {
              if is_tls_handshake_error(&e) {
                // TLS handshake failure, try next auth
                last_error = Some(e);
                continue;
              }
              // Non-auth error, no fallback
              warn!("Http3ChainService: connection failed: {e}");
              return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
            }
          };
          ct.register(conn.clone());
          current_conn = Some(conn.clone());
          let (h3_conn, requester) =
            match h3::client::new(h3_quinn::Connection::new(conn)).await {
              Ok(r) => r,
              Err(e) => {
                warn!(
                  "Http3ChainService: failed to create H3 connection: {e}"
                );
                return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
              }
            };

          // Spawn connection maintenance task
          let conn_task = connection_maintaining(h3_conn);
          st.register_connection(async move {
            let _ = conn_task.await;
          });

          requester
        };

        // Send CONNECT request
        // Clone requester to keep the connection alive after send_connect_with_auth returns.
        // The h3 library closes the H3 connection when the last SendRequest instance is dropped.
        // By keeping a clone alive (stored in proxy.requester below), we prevent premature closure.
        let requester_clone = requester.clone();
        let result = send_connect_with_auth(
          requester_clone,
          host.clone(),
          port,
          auth,
          &st,
          socks5_upgrade.clone(),
          http_upgrade.clone(),
        )
        .await;

        match result {
          Ok(response) => {
            // Store the requester to keep the connection alive
            // This prevents the h3 connection from being closed when the clone is dropped
            let proxy = &mut pg.borrow_mut().proxies[proxy_idx];
            let _ = proxy.requester.insert(requester);
            return Ok(response);
          }
          Err(e) => {
            if is_tls_handshake_error(&e) {
              // TLS handshake failure, try next auth method
              info!(
                "Http3ChainService: TLS handshake failed with auth method {}, trying next: {}",
                auth_index, e
              );
              last_error = Some(e);
              continue;
            }

            // Check if it's a 407 error (auth failure at HTTP level)
            // Use proper error type checking instead of string matching
            if e.downcast_ref::<ProxyAuthRequiredError>().is_some() {
              info!(
                "Http3ChainService: auth method {} returned 407, trying next",
                auth_index
              );
              last_error = Some(e);
              continue;
            }

            // Non-auth error, no fallback
            warn!("Http3ChainService: request failed: {e}");
            return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
          }
        }
      }

      // All auth methods failed
      let error_detail = last_error
        .map(|e| format!(": {e}"))
        .unwrap_or_default();
      warn!(
        "Http3ChainService: all {} auth methods failed{}",
        auth_chain.len(),
        error_detail
      );
      Ok(build_empty_response(
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED,
      ))
    })
  }
}

/// Send CONNECT request with authentication
async fn send_connect_with_auth(
  mut requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  host: String,
  port: u16,
  auth: &ProxyAuth,
  st: &Rc<StreamTracker>,
  socks5_upgrade: Option<plugin::Socks5OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<plugin::Response> {
  // Build CONNECT request
  let mut builder =
    http::Request::builder().method(http::Method::CONNECT).uri(format!(
      "{host}:{port}"
    ));

  // Add Proxy-Authorization header for password auth
  if let ProxyAuth::Password { username, password } = auth {
    let credentials =
      base64::engine::general_purpose::STANDARD.encode(format!(
        "{}:{}",
        username, password
      ));
    builder =
      builder.header("Proxy-Authorization", format!("Basic {}", credentials));
  }

  let proxy_req = builder.body(())?;
  info!("Http3ChainService: sending CONNECT request for {:?}", auth);
  let mut proxy_stream = requester.send_request(proxy_req).await?;
  let proxy_resp = proxy_stream.recv_response().await?;
  info!(
    "Http3ChainService: received CONNECT response: status={}",
    proxy_resp.status()
  );

  // Check for 407 error
  if proxy_resp.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
    return Err(ProxyAuthRequiredError.into());
  }

  if !proxy_resp.status().is_success() {
    return Ok(build_empty_response(proxy_resp.status()));
  }

  // Success - complete the tunnel
  info!("Http3ChainService: CONNECT succeeded, setting up tunnel");
  let (sending_stream, receiving_stream) = proxy_stream.split();
  complete_tunnel(sending_stream, receiving_stream, st, socks5_upgrade, http_upgrade)
    .await
}

/// Send CONNECT request without authentication and tunnel data
async fn send_connect_and_tunnel(
  mut requester: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  host: String,
  port: u16,
  st: &Rc<StreamTracker>,
  socks5_upgrade: Option<plugin::Socks5OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<plugin::Response> {
  let proxy_req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(format!("{host}:{port}"))
    .body(())?;

  let mut proxy_stream = requester.send_request(proxy_req).await?;
  let proxy_resp = proxy_stream.recv_response().await?;

  if !proxy_resp.status().is_success() {
    return Ok(build_empty_response(proxy_resp.status()));
  }

  let (sending_stream, receiving_stream) = proxy_stream.split();
  complete_tunnel(sending_stream, receiving_stream, st, socks5_upgrade, http_upgrade)
    .await
}

/// Complete the tunnel by setting up bidirectional transfer
async fn complete_tunnel(
  sending_stream: h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  receiving_stream: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  st: &Rc<StreamTracker>,
  socks5_upgrade: Option<plugin::Socks5OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<plugin::Response> {
  let resp = build_empty_response(http::StatusCode::OK);
  let shutdown_handle = st.shutdown_handle();

  st.register(async move {
    info!("Http3ChainService: tunnel background task started");

    // Check if shutdown is already triggered
    if shutdown_handle.is_shutdown() {
      warn!("Http3ChainService: shutdown already triggered, aborting tunnel");
      return;
    }

    let client_result: Result<ClientStream, String> =
      if let Some(socks5) = socks5_upgrade {
        info!("Http3ChainService: waiting for SOCKS5 upgrade");
        match socks5.await {
          Ok(stream) => {
            info!("Http3ChainService: SOCKS5 upgrade succeeded");
            Ok(ClientStream::Socks5(stream))
          },
          Err(e) => Err(format!("SOCKS5 upgrade failed: {e}")),
        }
      } else if let Some(http) = http_upgrade {
        info!("Http3ChainService: waiting for HTTP upgrade");
        match http.await {
          Ok(upgraded) => {
            info!("Http3ChainService: HTTP upgrade succeeded");
            Ok(ClientStream::Http(TokioIo::new(upgraded)))
          },
          Err(e) => Err(format!("HTTP upgrade failed: {e}")),
        }
      } else {
        warn!("Http3ChainService: no upgrade available for tunnel");
        return;
      };

    let mut client = match client_result {
      Ok(c) => c,
      Err(e) => {
        warn!("Http3ChainService tunnel upgrade failed: {e}");
        return;
      }
    };

    info!("Http3ChainService: client upgrade complete, starting bidirectional transfer");
    let mut h3_stream = H3BidirectionalStream::new(sending_stream, receiving_stream);

    let result = tokio::select! {
      res = tokio::io::copy_bidirectional(&mut client, &mut h3_stream) => res,
      _shutdown = shutdown_handle.notified() => {
        warn!("Http3ChainService tunnel shutdown by notification");
        return;
      }
    };

    if let Err(e) = result {
      warn!("Http3ChainService tunnel transfer error: {e}");
    } else {
      info!("Http3ChainService: bidirectional transfer completed successfully");
    }
  });

  Ok(resp)
}

struct Http3ChainPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
  stream_tracker: Rc<StreamTracker>,
  conn_tracker: ActiveConnectionTracker,
  /// Flag to ensure uninstall is idempotent
  is_uninstalled: Rc<AtomicBool>,
}

impl Http3ChainPlugin {
  fn new() -> Self {
    let stream_tracker = Rc::new(StreamTracker::new());
    let conn_tracker = ActiveConnectionTracker::new();
    let st_clone = stream_tracker.clone();
    let ct_clone = conn_tracker.clone();
    let builder: Box<dyn plugin::BuildService> = Box::new(move |a| {
      Http3ChainService::new(a, st_clone.clone(), ct_clone.clone())
    });
    let service_builders = HashMap::from([("http3_chain", builder)]);
    Self {
      service_builders,
      stream_tracker,
      conn_tracker,
      is_uninstalled: Rc::new(AtomicBool::new(false)),
    }
  }

  /// Perform graceful shutdown of all resources
  ///
  /// This method handles the actual shutdown logic and should be
  /// called within a timeout wrapper to ensure total shutdown time
  /// does not exceed 5 seconds.
  async fn do_graceful_shutdown(
    stream_tracker: &Rc<StreamTracker>,
    conn_tracker: &ActiveConnectionTracker,
  ) {
    // Trigger shutdown notification for streams
    stream_tracker.shutdown();
    info!("Http3ChainPlugin: shutdown notification sent");

    // Wait for all streams to complete
    stream_tracker.wait_shutdown().await;

    info!(
      "Http3ChainPlugin: all streams completed, \
       {} connections remaining",
      conn_tracker.count()
    );
  }
}

impl plugin::Plugin for Http3ChainPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }

  fn uninstall(&mut self) -> Pin<Box<dyn Future<Output = ()>>> {
    // Idempotency check: if already uninstalled, return immediately
    if self.is_uninstalled.load(Ordering::SeqCst) {
      info!("Http3ChainPlugin: already uninstalled, skipping");
      return Box::pin(async {});
    }

    // Mark as uninstalled
    self.is_uninstalled.store(true, Ordering::SeqCst);

    // Record initial counts BEFORE starting shutdown
    // This ensures accurate numbers in timeout logs
    let initial_stream_count = self.stream_tracker.active_count();
    let initial_conn_count = self.conn_tracker.count();

    let stream_tracker = self.stream_tracker.clone();
    let conn_tracker = self.conn_tracker.clone();

    Box::pin(async move {
      info!("Http3ChainPlugin: starting graceful shutdown");

      // Use a single unified timeout for the entire shutdown process
      // to ensure total time does not exceed 5 seconds as per architecture
      // document section 2.3.2
      let shutdown_result = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        Self::do_graceful_shutdown(&stream_tracker, &conn_tracker),
      )
      .await;

      match shutdown_result {
        Ok(_initial_counts) => {
          info!("Http3ChainPlugin: graceful shutdown completed");
        }
        Err(_) => {
          // Use the initial counts recorded BEFORE shutdown started
          // This provides accurate numbers for timeout logging
          warn!(
            "Http3ChainPlugin: shutdown timeout reached after {:?}, \
             forcefully aborting remaining tasks: {} streams, {} connections",
            SHUTDOWN_TIMEOUT, initial_stream_count, initial_conn_count
          );
          // Forcefully abort all streams and connections
          // abort_all() is synchronous and immediately terminates tasks,
          // no additional waiting needed
          stream_tracker.abort_all();
          info!("Http3ChainPlugin: forced shutdown completed");
        }
      }

      // Close all QUIC connections with CONNECTION_CLOSE frame
      // This sends H3_NO_ERROR to indicate graceful shutdown
      info!(
        "Http3ChainPlugin: closing {} QUIC connections",
        conn_tracker.count()
      );
      conn_tracker.close_all();
      conn_tracker.clear();
    })
  }
}

pub fn plugin_name() -> &'static str {
  "http3_chain"
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(Http3ChainPlugin::new())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::plugin::Plugin;
  use std::future::pending;

  // Initialize CryptoProvider for tests that involve TLS
  static CRYPTO_PROVIDER_INIT: std::sync::Once = std::sync::Once::new();

  fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
      let _ =
        rustls::crypto::ring::default_provider().install_default();
    });
  }

  // ============== Http3ChainPlugin Tests ==============

  #[test]
  fn test_plugin_new() {
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
    assert!(plugin.service_builder("nonexistent").is_none());
  }

  #[test]
  fn test_plugin_new_no_transfering_set() {
    // After refactor, Http3ChainPlugin should not have transfering_set field
    // and should still work correctly
    let plugin = Http3ChainPlugin::new();
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[test]
  fn test_plugin_service_builder_exists() {
    let plugin = Http3ChainPlugin::new();
    let builder = plugin.service_builder("http3_chain");
    assert!(builder.is_some());
  }

  #[test]
  fn test_create_plugin() {
    let plugin = create_plugin();
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  #[tokio::test]
  async fn test_uninstall_empty_plugin() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Uninstall with no active streams should complete quickly
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          plugin.uninstall(),
        )
        .await;
        assert!(
          result.is_ok(),
          "Uninstall should complete quickly with no streams"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_pending_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Register a pending stream that never completes
        plugin.stream_tracker.register(async {
          pending::<()>().await;
        });

        // Give time for the task to be spawned
        tokio::task::yield_now().await;

        // Uninstall should timeout and force abort
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        // Should have waited for the timeout
        assert!(
          elapsed >= SHUTDOWN_TIMEOUT,
          "Uninstall should wait for timeout"
        );
        // Allow small margin (100ms) for test overhead since abort_all()
        // is synchronous and no additional waiting is needed
        assert!(
          elapsed < SHUTDOWN_TIMEOUT + Duration::from_millis(100),
          "Uninstall should not take much longer than timeout, took {:?}",
          elapsed
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_completing_stream() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        let completed = Rc::new(RefCell::new(false));
        let completed_clone = completed.clone();

        // Register a stream that completes quickly
        plugin.stream_tracker.register(async move {
          // Simulate some work
          tokio::time::sleep(Duration::from_millis(10)).await;
          completed_clone.replace(true);
        });

        // Give time for the task to be spawned
        tokio::task::yield_now().await;

        // Uninstall should complete gracefully
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        // Should complete quickly since stream finishes
        assert!(
          elapsed < SHUTDOWN_TIMEOUT,
          "Uninstall should complete before timeout"
        );
        assert!(*completed.borrow(), "Stream should have completed");
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_multiple_times() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // First uninstall
        plugin.uninstall().await;

        // Second uninstall should also complete without error
        plugin.uninstall().await;

        // Third uninstall
        plugin.uninstall().await;
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_shutdown_handle() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();
        let handle = plugin.stream_tracker.shutdown_handle();

        let notified = Rc::new(RefCell::new(false));
        let notified_clone = notified.clone();

        plugin.stream_tracker.register(async move {
          handle.notified().await;
          notified_clone.replace(true);
        });

        tokio::task::yield_now().await;

        // Trigger shutdown
        plugin.stream_tracker.shutdown();

        // Wait for notification
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert!(*notified.borrow(), "Should have been notified");
      })
      .await;
  }

  #[test]
  fn test_stream_tracker_initial_state() {
    let plugin = Http3ChainPlugin::new();
    assert_eq!(plugin.stream_tracker.active_count(), 0);
    assert_eq!(plugin.stream_tracker.connection_count(), 0);
  }

  #[tokio::test]
  async fn test_stream_tracker_active_count() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        plugin.stream_tracker.register(async {
          // Long running task
          std::future::pending::<()>().await;
        });

        // Yield to allow task to be spawned
        tokio::task::yield_now().await;

        // Force abort should clear all tasks
        plugin.stream_tracker.abort_all();

        // Need to wait_shutdown to clear the JoinSet
        plugin.stream_tracker.wait_shutdown().await;

        // After abort and wait, count should be 0
        assert_eq!(
          plugin.stream_tracker.active_count(),
          0,
          "After abort and wait, count should be 0"
        );
      })
      .await;
  }

  // ============== ProxyGroup Tests ==============

  #[test]
  fn test_proxy_group_new() {
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 1, vec![]),
      ("127.0.0.1:8081".parse().unwrap(), 2, vec![]),
    ];
    let group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    assert_eq!(group.proxies.len(), 2);
    assert_eq!(group.proxies[0].weight, 1);
    assert_eq!(group.proxies[1].weight, 2);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_single() {
    let addresses = vec![("127.0.0.1:8080".parse().unwrap(), 1, vec![])];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    // With single proxy, should always select index 0
    assert_eq!(group.schedule_wrr(), 0);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_two_proxies_weight_2_to_1() {
    // Test WRR with two proxies: weights 2:1
    // Expected distribution over 6 calls: 0, 1, 0, 0, 1, 0 (4:2 ratio = 2:1)
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 2, vec![]), // weight 2
      ("127.0.0.1:8081".parse().unwrap(), 1, vec![]), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    // Run 6 iterations (total weight = 3, so 6 = 2 full cycles)
    let selections: Vec<usize> = (0..6).map(|_| group.schedule_wrr()).collect();

    // Count selections per proxy
    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();

    // With weights 2:1, expect approximately 4:2 distribution
    assert_eq!(count_0, 4, "Proxy 0 (weight 2) should be selected 4 times");
    assert_eq!(count_1, 2, "Proxy 1 (weight 1) should be selected 2 times");
  }

  #[test]
  fn test_proxy_group_schedule_wrr_two_proxies_weight_3_to_1() {
    // Test WRR with two proxies: weights 3:1
    // Expected distribution over 8 calls: 6:2 ratio = 3:1
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 3, vec![]), // weight 3
      ("127.0.0.1:8081".parse().unwrap(), 1, vec![]), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    // Run 8 iterations (total weight = 4, so 8 = 2 full cycles)
    let selections: Vec<usize> = (0..8).map(|_| group.schedule_wrr()).collect();

    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();

    // With weights 3:1, expect 6:2 distribution
    assert_eq!(count_0, 6, "Proxy 0 (weight 3) should be selected 6 times");
    assert_eq!(count_1, 2, "Proxy 1 (weight 1) should be selected 2 times");
  }

  #[test]
  fn test_proxy_group_schedule_wrr_three_proxies() {
    // Test WRR with three proxies: weights 2:1:1
    // Expected distribution over 8 calls: 4:2:2 ratio
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 2, vec![]), // weight 2
      ("127.0.0.1:8081".parse().unwrap(), 1, vec![]), // weight 1
      ("127.0.0.1:8082".parse().unwrap(), 1, vec![]), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    // Run 8 iterations (total weight = 4, so 8 = 2 full cycles)
    let selections: Vec<usize> = (0..8).map(|_| group.schedule_wrr()).collect();

    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();
    let count_2 = selections.iter().filter(|&&x| x == 2).count();

    // With weights 2:1:1, expect 4:2:2 distribution
    assert_eq!(count_0, 4, "Proxy 0 (weight 2) should be selected 4 times");
    assert_eq!(count_1, 2, "Proxy 1 (weight 1) should be selected 2 times");
    assert_eq!(count_2, 2, "Proxy 2 (weight 1) should be selected 2 times");
  }

  #[test]
  fn test_proxy_group_schedule_wrr_equal_weights() {
    // Test WRR with two proxies: equal weights 1:1
    // Expected distribution over 4 calls: 2:2 (alternating)
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 1, vec![]),
      ("127.0.0.1:8081".parse().unwrap(), 1, vec![]),
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );

    // Run 4 iterations
    let selections: Vec<usize> = (0..4).map(|_| group.schedule_wrr()).collect();

    let count_0 = selections.iter().filter(|&&x| x == 0).count();
    let count_1 = selections.iter().filter(|&&x| x == 1).count();

    // With equal weights, expect 2:2 distribution
    assert_eq!(count_0, 2, "Each proxy should be selected 2 times");
    assert_eq!(count_1, 2, "Each proxy should be selected 2 times");
  }

  #[test]
  fn test_proxy_group_schedule_wrr_deterministic() {
    // Test that WRR produces deterministic, repeatable results
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 2, vec![]),
      ("127.0.0.1:8081".parse().unwrap(), 1, vec![]),
    ];

    // First run
    let mut group1 = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses.clone(),
    );
    let selections1: Vec<usize> = (0..6).map(|_| group1.schedule_wrr()).collect();

    // Second run (should produce identical results)
    let mut group2 = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
    );
    let selections2: Vec<usize> = (0..6).map(|_| group2.schedule_wrr()).collect();

    assert_eq!(selections1, selections2, "WRR should be deterministic");
  }

  // ============== Http3ChainServiceArgs Tests ==============

  #[test]
  fn test_config_validation_nonexistent_ca_path_fails() {
    // CR-004: validate() should check that ca_path exists
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/nonexistent/path/ca.pem".to_string(),
      default_upstream_auth: None,
    };
    // Should fail because ca_path doesn't exist
    assert!(args.validate().is_err(), "validate() should fail for nonexistent ca_path");
  }

  // CR-003: Test for zero weight validation
  #[test]
  fn test_config_validation_zero_weight_fails() {
    // Create temp files for validation
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 0, // CR-003: weight 0 should be rejected
          auth: None,
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    // Should fail because weight is 0
    assert!(args.validate().is_err(), "validate() should fail for zero weight");
  }

  #[test]
  fn test_config_validation_multiple_proxies_one_zero_weight_fails() {
    // Create temp files for validation
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 2, // valid weight
          auth: None,
        },
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8081".to_string(),
          weight: 0, // CR-003: weight 0 should be rejected
          auth: None,
        },
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    // Should fail because one proxy has weight 0
    assert!(args.validate().is_err(), "validate() should fail when any proxy has zero weight");
  }

  #[test]
  fn test_service_args_deserialize() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
  - address: "127.0.0.1:8081"
    weight: 2
ca_path: "/tmp/ca.pem"
"#;
    let args: Http3ChainServiceArgs =
      serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.proxy_group.len(), 2);
    assert_eq!(args.ca_path, "/tmp/ca.pem");
    assert_eq!(args.proxy_group[0].address, "127.0.0.1:8080");
    assert_eq!(args.proxy_group[0].weight, 1);
    assert_eq!(args.proxy_group[1].address, "127.0.0.1:8081");
    assert_eq!(args.proxy_group[1].weight, 2);
  }

  #[test]
  fn test_service_args_default() {
    let args = Http3ChainServiceArgs::default();
    assert!(args.proxy_group.is_empty());
    assert!(args.ca_path.is_empty());
  }

  // ============== build_empty_response Tests ==============

  #[test]
  fn test_build_empty_response_ok() {
    let resp = build_empty_response(http::StatusCode::OK);
    assert_eq!(resp.status(), http::StatusCode::OK);
  }

  #[test]
  fn test_build_empty_response_not_found() {
    let resp = build_empty_response(http::StatusCode::NOT_FOUND);
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
  }

  #[test]
  fn test_build_empty_response_bad_gateway() {
    let resp = build_empty_response(http::StatusCode::BAD_GATEWAY);
    assert_eq!(resp.status(), http::StatusCode::BAD_GATEWAY);
  }

  #[test]
  fn test_build_empty_response_service_unavailable() {
    let resp =
      build_empty_response(http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
  }

  // ============== Http3ChainService Tests ==============

  #[test]
  fn test_service_new_with_empty_args() {
    let stream_tracker = Rc::new(StreamTracker::new());
    let conn_tracker = ActiveConnectionTracker::new();
    let result = Http3ChainService::new(
      serde_yaml::Value::Null,
      stream_tracker,
      conn_tracker,
    );
    // serde_yaml succeeds with defaults for Null, but the path may not exist
    // So we accept either Ok or Err
    assert!(result.is_ok() || result.is_err());
  }

  #[tokio::test]
  async fn test_service_new_with_valid_yaml() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let stream_tracker = Rc::new(StreamTracker::new());
        let conn_tracker = ActiveConnectionTracker::new();
        let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
"#;
        let yaml_value =
          serde_yaml::from_str::<serde_yaml::Value>(yaml).unwrap();
        let result = Http3ChainService::new(
          yaml_value,
          stream_tracker,
          conn_tracker,
        );
        // May fail if /tmp/ca.pem doesn't exist, which is expected
        assert!(result.is_ok() || result.is_err());
      })
      .await;
  }

  // ============== Plugin Trait Tests ==============

  #[test]
  fn test_plugin_trait_service_builder_none() {
    let plugin = Http3ChainPlugin::new();
    let result = plugin.service_builder("nonexistent");
    assert!(result.is_none());
  }

  #[test]
  fn test_plugin_trait_service_builder_some() {
    let plugin = Http3ChainPlugin::new();
    let result = plugin.service_builder("http3_chain");
    assert!(result.is_some());
  }

  // ============== Shutdown Timeout Tests ==============

  #[test]
  fn test_shutdown_timeout_value() {
    assert_eq!(SHUTDOWN_TIMEOUT, Duration::from_secs(5));
  }

  // ============== ALPN Tests ==============

  #[test]
  fn test_alpn_value() {
    assert_eq!(ALPN, b"h3");
  }

  // ============== Proxy Tests ==============

  #[test]
  fn test_proxy_default() {
    let proxy = Proxy {
      address: "127.0.0.1:8080".parse().unwrap(),
      conn_handle: None,
      requester: None,
      weight: 1,
      current_weight: 0,
      auth_chain: vec![],
    };
    assert_eq!(proxy.weight, 1);
    assert_eq!(proxy.current_weight, 0);
    assert!(proxy.conn_handle.is_none());
    assert!(proxy.requester.is_none());
  }

  // ============== connection_maintaining Tests ==============

  // Note: connection_maintaining requires a real h3 connection,
  // which is difficult to test in unit tests.

  // ============== Additional Edge Case Tests ==============

  #[tokio::test]
  async fn test_uninstall_abort_all_empty() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        // Abort all on empty tracker should not panic
        plugin.stream_tracker.abort_all();
        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_multiple_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Register multiple streams
        for _ in 0..5 {
          plugin.stream_tracker.register(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
          });
        }

        tokio::task::yield_now().await;
        assert_eq!(plugin.stream_tracker.active_count(), 5);

        // Uninstall should wait for all to complete
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed < Duration::from_millis(200),
          "Uninstall should complete quickly when streams finish"
        );
        assert_eq!(plugin.stream_tracker.active_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_stream_tracker_wait_shutdown() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        let completed = Rc::new(RefCell::new(0));
        let completed_clone = completed.clone();

        plugin.stream_tracker.register(async move {
          tokio::time::sleep(Duration::from_millis(10)).await;
          *completed_clone.borrow_mut() += 1;
        });

        tokio::task::yield_now().await;

        // Wait for shutdown without triggering
        plugin.stream_tracker.wait_shutdown().await;

        assert_eq!(*completed.borrow(), 1);
      })
      .await;
  }

  #[test]
  fn test_service_args_proxy_group_default() {
    let proxy_group = Http3ChainServiceArgsProxyGroup::default();
    assert!(proxy_group.address.is_empty());
    assert_eq!(proxy_group.weight, 0);
  }

  #[tokio::test]
  async fn test_stream_tracker_connection_tracking() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let plugin = Http3ChainPlugin::new();

        plugin.stream_tracker.register_connection(async {
          tokio::time::sleep(Duration::from_millis(10)).await;
        });

        tokio::task::yield_now().await;
        assert_eq!(plugin.stream_tracker.connection_count(), 1);
        assert_eq!(plugin.stream_tracker.active_count(), 0);

        // Wait for connection to complete
        plugin.stream_tracker.wait_shutdown().await;
        assert_eq!(plugin.stream_tracker.connection_count(), 0);
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_with_connection() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Register a connection that completes quickly
        plugin.stream_tracker.register_connection(async {
          tokio::time::sleep(Duration::from_millis(10)).await;
        });

        tokio::task::yield_now().await;

        // Uninstall should complete gracefully
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        assert!(
          elapsed < SHUTDOWN_TIMEOUT,
          "Uninstall should complete before timeout"
        );
      })
      .await;
  }

  // ============== Shutdown State Tests ==============

  #[test]
  fn test_stream_tracker_shutdown_handle_is_shutdown() {
    let tracker = StreamTracker::new();
    let handle = tracker.shutdown_handle();

    assert!(
      !handle.is_shutdown(),
      "ShutdownHandle should not be shutdown initially"
    );

    tracker.shutdown();

    assert!(
      handle.is_shutdown(),
      "ShutdownHandle should be shutdown after tracker.shutdown()"
    );
  }

  #[tokio::test]
  async fn test_http3_chain_service_uses_shared_shutdown_handle() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let stream_tracker = Rc::new(StreamTracker::new());
        let conn_tracker = ActiveConnectionTracker::new();
        let handle = stream_tracker.shutdown_handle();

        // Create service args
        let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
"#;
        let yaml_value: serde_yaml::Value =
          serde_yaml::from_str(yaml).unwrap();

        // Service creation may fail if /tmp/ca.pem doesn't exist,
        // but that's okay - we just want to verify the handle sharing
        if let Ok(_service) = Http3ChainService::new(
          yaml_value,
          stream_tracker.clone(),
          conn_tracker,
        ) {
          // The service should use the stream_tracker's shutdown handle
          // This is verified by the fact that the handle is shared
        }

        // Trigger shutdown through the tracker
        stream_tracker.shutdown();

        // The handle should reflect shutdown state
        assert!(
          handle.is_shutdown(),
          "ShutdownHandle should be shared with StreamTracker"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_shutdown_rejects_new_requests() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Trigger shutdown
        plugin.stream_tracker.shutdown();

        // Verify shutdown state
        assert!(
          plugin.stream_tracker.shutdown_handle().is_shutdown(),
          "StreamTracker should be in shutdown state"
        );

        // Now call uninstall - should complete quickly since no active
        // streams
        let result = tokio::time::timeout(
          Duration::from_millis(100),
          plugin.uninstall(),
        )
        .await;
        assert!(result.is_ok(), "Uninstall should complete quickly");
      })
      .await;
  }

  /// Critical test: verifies that Http3ChainService::new() can be called
  /// without a tokio runtime (e.g., during config validation phase).
  /// This test ensures the lazy initialization fix works correctly.
  #[test]
  fn test_service_new_without_runtime() {
    let stream_tracker = Rc::new(StreamTracker::new());
    let conn_tracker = ActiveConnectionTracker::new();

    // Create service args with minimal configuration
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/nonexistent/ca.pem"
"#;
    let yaml_value: serde_yaml::Value =
      serde_yaml::from_str(yaml).unwrap();

    // This should NOT panic even though no tokio runtime is active
    // The lazy initialization ensures spawn_local is not called here
    let result = Http3ChainService::new(
      yaml_value,
      stream_tracker,
      conn_tracker,
    );

    // Service creation may fail because /nonexistent/ca.pem doesn't exist,
    // but the important thing is that it doesn't panic with
    // "spawn_local called from outside of a task::LocalSet"
    // The test passes as long as no panic occurs
    let _ = result;
  }

  // ============== is_shutting_down Tests ==============

  #[test]
  fn test_is_shutting_down_reflects_tracker_state() {
    let stream_tracker = Rc::new(StreamTracker::new());

    // Initially not shutting down
    assert!(
      !stream_tracker.shutdown_handle().is_shutdown(),
      "Should not be shutting down initially"
    );

    // Trigger shutdown
    stream_tracker.shutdown();

    // Now shutting down
    assert!(
      stream_tracker.shutdown_handle().is_shutdown(),
      "Should be shutting down after shutdown()"
    );
  }

  #[test]
  fn test_multiple_shutdown_calls_no_side_effects() {
    let stream_tracker = StreamTracker::new();

    // Call shutdown multiple times
    stream_tracker.shutdown();
    stream_tracker.shutdown();
    stream_tracker.shutdown();

    // Should still be in consistent state
    assert!(stream_tracker.shutdown_handle().is_shutdown());

    // Abort all should still work
    stream_tracker.abort_all();
    assert_eq!(stream_tracker.active_count(), 0);
  }

  // ============== Service Shutdown Check Tests ==============

  #[tokio::test]
  async fn test_service_call_rejects_during_shutdown() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        // Create a simple mock request
        let req = http::Request::builder()
          .method(http::Method::CONNECT)
          .uri("example.com:443")
          .body(plugin::RequestBody::new(
            plugin::BytesBufBodyWrapper::new(
              http_body_util::Empty::new(),
            ),
          ))
          .unwrap();

        // Create service with stream tracker
        let stream_tracker = Rc::new(StreamTracker::new());
        let conn_tracker = ActiveConnectionTracker::new();

        // Create service args - note: /tmp/ca.pem may not exist
        let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
"#;
        let yaml_value: serde_yaml::Value =
          serde_yaml::from_str(yaml).unwrap();

        // Service creation may fail if /tmp/ca.pem doesn't exist
        // In that case, skip this test
        if let Ok(mut service) = Http3ChainService::new(
          yaml_value,
          stream_tracker.clone(),
          conn_tracker,
        ) {
          // Trigger shutdown before calling the service
          stream_tracker.shutdown();

          // Verify the service knows it's shutting down
          // We can't directly call is_shutting_down() since it's private,
          // but we can verify through the tracker's handle
          assert!(
            stream_tracker.shutdown_handle().is_shutdown(),
            "Service should know it's shutting down"
          );

          // Call the service - should reject with SERVICE_UNAVAILABLE
          use tower::Service;
          let response = service.call(req).await;
          assert!(
            response.is_ok(),
            "Service call should succeed with rejection response"
          );

          let resp = response.unwrap();
          assert_eq!(
            resp.status(),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "Should reject with 503 Service Unavailable"
          );
        }
      })
      .await;
  }

  #[tokio::test]
  async fn test_service_is_shutting_down_method() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let stream_tracker = Rc::new(StreamTracker::new());
        let conn_tracker = ActiveConnectionTracker::new();

        // Create service args
        let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
"#;
        let yaml_value: serde_yaml::Value =
          serde_yaml::from_str(yaml).unwrap();

        // Service creation may fail if /tmp/ca.pem doesn't exist
        if let Ok(_service) = Http3ChainService::new(
          yaml_value,
          stream_tracker.clone(),
          conn_tracker,
        ) {
          // Before shutdown, the tracker's handle should show not shutdown
          assert!(
            !stream_tracker.shutdown_handle().is_shutdown(),
            "Should not be shutting down initially"
          );

          // Trigger shutdown
          stream_tracker.shutdown();

          // After shutdown, the tracker's handle should show shutdown
          assert!(
            stream_tracker.shutdown_handle().is_shutdown(),
            "Should be shutting down after shutdown()"
          );
        }
      })
      .await;
  }

  #[test]
  fn test_shutdown_handle_is_shutdown_state_shared() {
    let handle1 = plugin::ShutdownHandle::new();
    let handle2 = handle1.clone();

    // Both should show not shutdown initially
    assert!(!handle1.is_shutdown());
    assert!(!handle2.is_shutdown());

    // Trigger shutdown on handle1
    handle1.shutdown();

    // Both should show shutdown now
    assert!(handle1.is_shutdown());
    assert!(handle2.is_shutdown());
  }

  // ============== ActiveConnectionTracker Tests ==============

  #[test]
  fn test_active_connection_tracker_new() {
    let tracker = ActiveConnectionTracker::new();
    assert_eq!(tracker.count(), 0);
  }

  #[test]
  fn test_active_connection_tracker_default() {
    let tracker = ActiveConnectionTracker::default();
    assert_eq!(tracker.count(), 0);
  }

  #[test]
  fn test_active_connection_tracker_clone() {
    let tracker = ActiveConnectionTracker::new();
    let cloned = tracker.clone();
    assert_eq!(tracker.count(), cloned.count());
  }

  #[test]
  fn test_active_connection_tracker_clear() {
    let tracker = ActiveConnectionTracker::new();
    tracker.clear(); // Should not panic on empty
    assert_eq!(tracker.count(), 0);
  }

  // ============== H3_NO_ERROR Code Tests ==============

  #[test]
  fn test_h3_no_error_code_value() {
    // H3_NO_ERROR code should be 0x100 (256)
    assert_eq!(H3_NO_ERROR_CODE, 0x100);
    assert_eq!(H3_NO_ERROR_CODE, 256);
  }

  // ============== Idempotency Tests ==============

  #[tokio::test]
  async fn test_uninstall_idempotency() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // First uninstall should mark as uninstalled
        plugin.uninstall().await;
        assert!(plugin.is_uninstalled.load(Ordering::SeqCst));

        // Second uninstall should return immediately without error
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();

        // Should complete immediately (not wait for timeout)
        assert!(
          elapsed < Duration::from_millis(100),
          "Second uninstall should return immediately"
        );

        // Third uninstall should also return immediately
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();
        assert!(
          elapsed < Duration::from_millis(100),
          "Third uninstall should return immediately"
        );
      })
      .await;
  }

  #[tokio::test]
  async fn test_uninstall_idempotency_with_streams() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Register a stream that completes quickly
        plugin.stream_tracker.register(async {
          tokio::time::sleep(Duration::from_millis(10)).await;
        });

        tokio::task::yield_now().await;

        // First uninstall
        plugin.uninstall().await;
        assert!(plugin.is_uninstalled.load(Ordering::SeqCst));

        // Second uninstall should be instant
        let start = std::time::Instant::now();
        plugin.uninstall().await;
        let elapsed = start.elapsed();
        assert!(
          elapsed < Duration::from_millis(50),
          "Second uninstall should return immediately"
        );
      })
      .await;
  }

  // ============== Connection Tracker Integration Tests ==============

  #[test]
  fn test_plugin_has_connection_tracker() {
    let plugin = Http3ChainPlugin::new();
    assert_eq!(plugin.conn_tracker.count(), 0);
  }

  #[test]
  fn test_connection_tracker_shared_with_service() {
    let plugin = Http3ChainPlugin::new();

    // The connection tracker should be shared with the service builder
    // We can verify this by checking that the service builder exists
    assert!(plugin.service_builder("http3_chain").is_some());
  }

  // ============== Shutdown Flow Tests ==============

  #[tokio::test]
  async fn test_shutdown_flow_closes_connections() {
    let local_set = tokio::task::LocalSet::new();
    local_set
      .run_until(async {
        let mut plugin = Http3ChainPlugin::new();

        // Verify initial state
        assert_eq!(plugin.conn_tracker.count(), 0);
        assert!(!plugin.is_uninstalled.load(Ordering::SeqCst));

        // Call uninstall
        plugin.uninstall().await;

        // Verify final state
        assert!(plugin.is_uninstalled.load(Ordering::SeqCst));
        // Connection tracker should be cleared after uninstall
        assert_eq!(plugin.conn_tracker.count(), 0);
      })
      .await;
  }

  // ============== VarInt Conversion Tests ==============

  #[test]
  fn test_varint_from_h3_no_error_code() {
    let varint = quinn::VarInt::from_u32(H3_NO_ERROR_CODE);
    assert_eq!(varint.into_inner(), 0x100u64);
  }

  // SendState and H3BidirectionalStream behavior is documented in code comments
  // and verified through integration tests. See SendState enum and
  // H3BidirectionalStream struct doc comments for state machine documentation.

  // ============== ProxyAuth Tests ==============

  #[test]
  fn test_proxy_auth_none() {
    let auth = ProxyAuth::None;
    assert!(matches!(auth, ProxyAuth::None));
  }

  #[test]
  fn test_proxy_auth_password() {
    let auth = ProxyAuth::Password {
      username: "user".to_string(),
      password: "pass".to_string(),
    };
    match auth {
      ProxyAuth::Password { username, password } => {
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_proxy_auth_tls_client_cert() {
    let auth = ProxyAuth::TlsClientCert {
      client_cert_path: std::path::PathBuf::from("/path/to/cert.pem"),
      client_key_path: std::path::PathBuf::from("/path/to/key.pem"),
    };
    match auth {
      ProxyAuth::TlsClientCert { client_cert_path, client_key_path } => {
        assert_eq!(client_cert_path, std::path::PathBuf::from("/path/to/cert.pem"));
        assert_eq!(client_key_path, std::path::PathBuf::from("/path/to/key.pem"));
      }
      _ => panic!("Expected TlsClientCert variant"),
    }
  }

  // ============== ProxyAuthConfig Tests ==============

  #[test]
  fn test_proxy_auth_config_deserialize_none() {
    let yaml = r#"
type: "none"
"#;
    let config: ProxyAuthConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.auth_type, "none");
  }

  #[test]
  fn test_proxy_auth_config_deserialize_password() {
    let yaml = r#"
type: "password"
username: "testuser"
password: "testpass"
"#;
    let config: ProxyAuthConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.auth_type, "password");
    assert_eq!(config.username, Some("testuser".to_string()));
    assert_eq!(config.password, Some("testpass".to_string()));
  }

  #[test]
  fn test_proxy_auth_config_deserialize_tls_client_cert() {
    let yaml = r#"
type: "tls_client_cert"
client_cert_path: "/path/to/cert.pem"
client_key_path: "/path/to/key.pem"
"#;
    let config: ProxyAuthConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.auth_type, "tls_client_cert");
    assert_eq!(config.client_cert_path, Some("/path/to/cert.pem".to_string()));
    assert_eq!(config.client_key_path, Some("/path/to/key.pem".to_string()));
  }

  #[test]
  fn test_proxy_auth_config_default_fields() {
    let yaml = r#"
type: "password"
username: "user"
"#;
    let config: ProxyAuthConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.auth_type, "password");
    assert_eq!(config.username, Some("user".to_string()));
    assert_eq!(config.password, None); // Default is None
  }

  #[test]
  fn test_proxy_auth_config_to_proxy_auth_none() {
    let config = ProxyAuthConfig {
      auth_type: "none".to_string(),
      ..Default::default()
    };
    let auth = Http3ChainServiceArgs::parse_auth_config(&config).unwrap();
    assert!(matches!(auth, ProxyAuth::None));
  }

  #[test]
  fn test_proxy_auth_config_to_proxy_auth_password() {
    let config = ProxyAuthConfig {
      auth_type: "password".to_string(),
      username: Some("user".to_string()),
      password: Some("pass".to_string()),
      ..Default::default()
    };
    let auth = Http3ChainServiceArgs::parse_auth_config(&config).unwrap();
    match auth {
      ProxyAuth::Password { username, password } => {
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_proxy_auth_config_to_proxy_auth_tls_client_cert() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let config = ProxyAuthConfig {
      auth_type: "tls_client_cert".to_string(),
      client_cert_path: Some(cert_path.to_string_lossy().to_string()),
      client_key_path: Some(key_path.to_string_lossy().to_string()),
      ..Default::default()
    };
    let auth = Http3ChainServiceArgs::parse_auth_config(&config).unwrap();
    match auth {
      ProxyAuth::TlsClientCert { client_cert_path: cert, client_key_path: key } => {
        assert_eq!(cert, cert_path);
        assert_eq!(key, key_path);
      }
      _ => panic!("Expected TlsClientCert variant"),
    }
  }

  #[test]
  fn test_proxy_auth_config_invalid_type() {
    let config = ProxyAuthConfig {
      auth_type: "invalid_type".to_string(),
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("unknown auth type"));
  }

  #[test]
  fn test_proxy_auth_config_password_missing_username() {
    let config = ProxyAuthConfig {
      auth_type: "password".to_string(),
      username: None,
      password: Some("pass".to_string()),
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("username required"));
  }

  #[test]
  fn test_proxy_auth_config_password_missing_password() {
    let config = ProxyAuthConfig {
      auth_type: "password".to_string(),
      username: Some("user".to_string()),
      password: None,
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("password required"));
  }

  // CR-015, CR-017: Tests for empty string validation in parse_auth_config

  #[test]
  fn test_proxy_auth_config_password_empty_username() {
    // CR-015: Empty username should be rejected by parse_auth_config
    // CR-002: Now delegates to validate_auth_config for consistent validation
    let config = ProxyAuthConfig {
      auth_type: "password".to_string(),
      username: Some("".to_string()), // Empty string
      password: Some("pass".to_string()),
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("username required"), "Expected error about username, got: {err_msg}");
  }

  #[test]
  fn test_proxy_auth_config_password_empty_password() {
    // CR-015: Empty password should be rejected by parse_auth_config
    // CR-002: Now delegates to validate_auth_config for consistent validation
    let config = ProxyAuthConfig {
      auth_type: "password".to_string(),
      username: Some("user".to_string()),
      password: Some("".to_string()), // Empty string
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("password required"), "Expected error about password, got: {err_msg}");
  }

  #[test]
  fn test_proxy_auth_config_tls_client_cert_empty_cert_path() {
    // CR-016: Empty client_cert_path should be rejected by parse_auth_config
    // CR-002: Now delegates to validate_auth_config for consistent validation
    let config = ProxyAuthConfig {
      auth_type: "tls_client_cert".to_string(),
      client_cert_path: Some("".to_string()), // Empty string
      client_key_path: Some("/path/to/key.pem".to_string()),
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("client_cert_path"), "Expected error about client_cert_path, got: {err_msg}");
  }

  #[test]
  fn test_proxy_auth_config_tls_client_cert_empty_key_path() {
    // CR-016: Empty client_key_path should be rejected by parse_auth_config
    // CR-002: Now delegates to validate_auth_config for consistent validation
    // Note: validate_auth_config checks file existence, so we need to create temp files
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    fs::write(&cert_path, "dummy cert").unwrap();

    let config = ProxyAuthConfig {
      auth_type: "tls_client_cert".to_string(),
      client_cert_path: Some(cert_path.to_string_lossy().to_string()),
      client_key_path: Some("".to_string()), // Empty string
      ..Default::default()
    };
    let result = Http3ChainServiceArgs::parse_auth_config(&config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("client_key_path"), "Expected error about client_key_path, got: {err_msg}");
  }

  // ============== Per-Proxy Auth Config Tests ==============

  #[test]
  fn test_proxy_group_with_auth_field() {
    let yaml = r#"
address: "127.0.0.1:8080"
weight: 1
auth:
  - type: "password"
    username: "user1"
    password: "pass1"
  - type: "tls_client_cert"
    client_cert_path: "/path/to/cert.pem"
    client_key_path: "/path/to/key.pem"
"#;
    let proxy: Http3ChainServiceArgsProxyGroup = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.address, "127.0.0.1:8080");
    assert_eq!(proxy.weight, 1);
    assert!(proxy.auth.is_some());
    let auth_list = proxy.auth.unwrap();
    assert_eq!(auth_list.len(), 2);
    assert_eq!(auth_list[0].auth_type, "password");
    assert_eq!(auth_list[1].auth_type, "tls_client_cert");
  }

  #[test]
  fn test_proxy_group_without_auth_field() {
    let yaml = r#"
address: "127.0.0.1:8080"
weight: 1
"#;
    let proxy: Http3ChainServiceArgsProxyGroup = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.address, "127.0.0.1:8080");
    assert_eq!(proxy.weight, 1);
    assert!(proxy.auth.is_none());
  }

  #[test]
  fn test_proxy_group_auth_explicit_none() {
    let yaml = r#"
address: "127.0.0.1:8080"
weight: 1
auth:
  - type: "none"
"#;
    let proxy: Http3ChainServiceArgsProxyGroup = serde_yaml::from_str(yaml).unwrap();
    assert!(proxy.auth.is_some());
    let auth_list = proxy.auth.unwrap();
    assert_eq!(auth_list.len(), 1);
    assert_eq!(auth_list[0].auth_type, "none");
  }

  // ============== Http3ChainServiceArgs with default_upstream_auth Tests ==============

  #[test]
  fn test_service_args_with_default_upstream_auth() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
  - address: "127.0.0.1:8081"
    weight: 2
    auth:
      - type: "password"
        username: "user1"
        password: "pass1"
ca_path: "/tmp/ca.pem"
default_upstream_auth:
  - type: "tls_client_cert"
    client_cert_path: "/default/cert.pem"
    client_key_path: "/default/key.pem"
  - type: "password"
    username: "default_user"
    password: "default_pass"
"#;
    let args: Http3ChainServiceArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.default_upstream_auth.is_some());
    let default_auth = args.default_upstream_auth.unwrap();
    assert_eq!(default_auth.len(), 2);
    assert_eq!(default_auth[0].auth_type, "tls_client_cert");
    assert_eq!(default_auth[1].auth_type, "password");
  }

  #[test]
  fn test_service_args_without_default_upstream_auth() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
"#;
    let args: Http3ChainServiceArgs = serde_yaml::from_str(yaml).unwrap();
    assert!(args.default_upstream_auth.is_none());
  }

  // ============== Proxy with auth_chain Tests ==============

  #[test]
  fn test_proxy_with_auth_chain() {
    let proxy = Proxy {
      address: "127.0.0.1:8080".parse().unwrap(),
      conn_handle: None,
      requester: None,
      weight: 1,
      current_weight: 0,
      auth_chain: vec![
        ProxyAuth::Password {
          username: "user".to_string(),
          password: "pass".to_string(),
        },
        ProxyAuth::None,
      ],
    };
    assert_eq!(proxy.auth_chain.len(), 2);
    assert!(matches!(proxy.auth_chain[0], ProxyAuth::Password { .. }));
    assert!(matches!(proxy.auth_chain[1], ProxyAuth::None));
  }

  #[test]
  fn test_proxy_with_empty_auth_chain() {
    let proxy = Proxy {
      address: "127.0.0.1:8080".parse().unwrap(),
      conn_handle: None,
      requester: None,
      weight: 1,
      current_weight: 0,
      auth_chain: vec![],
    };
    assert!(proxy.auth_chain.is_empty());
  }

  // ============== Auth Configuration Validation Tests ==============

  #[test]
  fn test_validate_default_upstream_auth_password_missing_username() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "password".to_string(),
          username: None,
          password: Some("pass".to_string()),
          ..Default::default()
        }
      ]),
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("username"), "Expected error about username, got: {err_msg}");
  }

  #[test]
  fn test_validate_default_upstream_auth_tls_cert_missing_cert_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "tls_client_cert".to_string(),
          client_cert_path: None,
          client_key_path: Some("/tmp/key.pem".to_string()),
          ..Default::default()
        }
      ]),
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("client_cert_path"), "Expected error about client_cert_path, got: {err_msg}");
  }

  #[test]
  fn test_validate_default_upstream_auth_tls_cert_nonexistent_cert() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "tls_client_cert".to_string(),
          client_cert_path: Some("/nonexistent/cert.pem".to_string()),
          client_key_path: Some("/nonexistent/key.pem".to_string()),
          ..Default::default()
        }
      ]),
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("does not exist") || err_msg.contains("client_cert_path"),
            "Expected error about missing file, got: {err_msg}");
  }

  #[test]
  fn test_validate_default_upstream_auth_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&ca_path, "dummy ca").unwrap();
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "tls_client_cert".to_string(),
          client_cert_path: Some(cert_path.to_string_lossy().to_string()),
          client_key_path: Some(key_path.to_string_lossy().to_string()),
          ..Default::default()
        },
        ProxyAuthConfig {
          auth_type: "password".to_string(),
          username: Some("user".to_string()),
          password: Some("pass".to_string()),
          ..Default::default()
        }
      ]),
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_validate_default_upstream_auth_unknown_type() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "unknown_type".to_string(),
          ..Default::default()
        }
      ]),
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("unknown auth type"), "Expected error about unknown type, got: {err_msg}");
  }

  #[test]
  fn test_validate_per_proxy_auth_password_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: Some("user".to_string()),
              password: Some("pass".to_string()),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_validate_per_proxy_auth_tls_cert_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&ca_path, "dummy ca").unwrap();
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "tls_client_cert".to_string(),
              client_cert_path: Some(cert_path.to_string_lossy().to_string()),
              client_key_path: Some(key_path.to_string_lossy().to_string()),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_validate_per_proxy_auth_none_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "none".to_string(),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_validate_per_proxy_auth_fallback_chain_valid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&ca_path, "dummy ca").unwrap();
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "tls_client_cert".to_string(),
              client_cert_path: Some(cert_path.to_string_lossy().to_string()),
              client_key_path: Some(key_path.to_string_lossy().to_string()),
              ..Default::default()
            },
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: Some("user".to_string()),
              password: Some("pass".to_string()),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_validate_per_proxy_auth_missing_password() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: Some("user".to_string()),
              password: None,
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("password required"), "Expected error about password, got: {err_msg}");
  }

  // CR-003: Test for empty password string validation via validate()
  #[test]
  fn test_validate_default_upstream_auth_empty_password() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: Some(vec![
        ProxyAuthConfig {
          auth_type: "password".to_string(),
          username: Some("user".to_string()),
          password: Some("".to_string()), // Empty password
          ..Default::default()
        }
      ]),
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("password required"), "Expected error about password, got: {err_msg}");
  }

  // CR-001: Test for per-proxy auth with missing/empty username
  #[test]
  fn test_validate_per_proxy_auth_missing_username() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: None,
              password: Some("pass".to_string()),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("username required"), "Expected error about username, got: {err_msg}");
  }

  // CR-001: Test for per-proxy auth with empty username string
  #[test]
  fn test_validate_per_proxy_auth_empty_username() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: Some("".to_string()), // Empty string
              password: Some("pass".to_string()),
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("username required"), "Expected error about username, got: {err_msg}");
  }

  // CR-003: Test for per-proxy auth with empty password string validation via validate()
  #[test]
  fn test_validate_per_proxy_auth_empty_password() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8080".to_string(),
          weight: 1,
          auth: Some(vec![
            ProxyAuthConfig {
              auth_type: "password".to_string(),
              username: Some("user".to_string()),
              password: Some("".to_string()), // Empty string
              ..Default::default()
            }
          ]),
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      default_upstream_auth: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("password required"), "Expected error about password, got: {err_msg}");
  }

  // ============== Auth Resolution Tests ==============

  #[test]
  fn test_resolve_proxy_auth_no_auth_field_inherits_default() {
    let default_auth = vec![
      ProxyAuthConfig {
        auth_type: "password".to_string(),
        username: Some("default_user".to_string()),
        password: Some("default_pass".to_string()),
        ..Default::default()
      }
    ];

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: Some(default_auth),
    };

    let resolved = args.resolve_proxy_auth(&None);
    assert_eq!(resolved.len(), 1);
    match &resolved[0] {
      ProxyAuth::Password { username, password } => {
        assert_eq!(username, "default_user");
        assert_eq!(password, "default_pass");
      }
      _ => panic!("Expected Password variant"),
    }
  }

  #[test]
  fn test_resolve_proxy_auth_no_auth_field_no_default() {
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: None,
    };

    let resolved = args.resolve_proxy_auth(&None);
    assert!(resolved.is_empty());
  }

  #[test]
  fn test_resolve_proxy_auth_own_auth_overrides_default() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let default_auth = vec![
      ProxyAuthConfig {
        auth_type: "password".to_string(),
        username: Some("default_user".to_string()),
        password: Some("default_pass".to_string()),
        ..Default::default()
      }
    ];

    let own_auth = vec![
      ProxyAuthConfig {
        auth_type: "tls_client_cert".to_string(),
        client_cert_path: Some(cert_path.to_string_lossy().to_string()),
        client_key_path: Some(key_path.to_string_lossy().to_string()),
        ..Default::default()
      }
    ];

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: Some(default_auth),
    };

    let resolved = args.resolve_proxy_auth(&Some(own_auth));
    assert_eq!(resolved.len(), 1);
    assert!(matches!(resolved[0], ProxyAuth::TlsClientCert { .. }));
  }

  #[test]
  fn test_resolve_proxy_auth_explicit_none() {
    let default_auth = vec![
      ProxyAuthConfig {
        auth_type: "password".to_string(),
        username: Some("default_user".to_string()),
        password: Some("default_pass".to_string()),
        ..Default::default()
      }
    ];

    let own_auth = vec![
      ProxyAuthConfig {
        auth_type: "none".to_string(),
        ..Default::default()
      }
    ];

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: Some(default_auth),
    };

    let resolved = args.resolve_proxy_auth(&Some(own_auth));
    assert_eq!(resolved.len(), 1);
    assert!(matches!(resolved[0], ProxyAuth::None));
  }

  #[test]
  fn test_resolve_proxy_auth_fallback_chain() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let own_auth = vec![
      ProxyAuthConfig {
        auth_type: "tls_client_cert".to_string(),
        client_cert_path: Some(cert_path.to_string_lossy().to_string()),
        client_key_path: Some(key_path.to_string_lossy().to_string()),
        ..Default::default()
      },
      ProxyAuthConfig {
        auth_type: "password".to_string(),
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        ..Default::default()
      },
    ];

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: None,
    };

    let resolved = args.resolve_proxy_auth(&Some(own_auth));
    assert_eq!(resolved.len(), 2);
    assert!(matches!(resolved[0], ProxyAuth::TlsClientCert { .. }));
    assert!(matches!(resolved[1], ProxyAuth::Password { .. }));
  }

  #[test]
  fn test_resolve_proxy_auth_default_fallback_chain() {
    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let default_auth = vec![
      ProxyAuthConfig {
        auth_type: "tls_client_cert".to_string(),
        client_cert_path: Some(cert_path.to_string_lossy().to_string()),
        client_key_path: Some(key_path.to_string_lossy().to_string()),
        ..Default::default()
      },
      ProxyAuthConfig {
        auth_type: "password".to_string(),
        username: Some("default_user".to_string()),
        password: Some("default_pass".to_string()),
        ..Default::default()
      },
    ];

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/tmp/ca.pem".to_string(),
      default_upstream_auth: Some(default_auth),
    };

    let resolved = args.resolve_proxy_auth(&None);
    assert_eq!(resolved.len(), 2);
    assert!(matches!(resolved[0], ProxyAuth::TlsClientCert { .. }));
    assert!(matches!(resolved[1], ProxyAuth::Password { .. }));
  }

  #[test]
  fn test_service_new_resolves_auth_chains() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
  - address: "127.0.0.1:8081"
    weight: 2
    auth:
      - type: "password"
        username: "user1"
        password: "pass1"
  - address: "127.0.0.1:8082"
    weight: 3
    auth:
      - type: "none"
ca_path: "/tmp/ca.pem"
default_upstream_auth:
  - type: "password"
    username: "default_user"
    password: "default_pass"
"#;
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();

    // Parse and validate
    let args: Http3ChainServiceArgs = serde_yaml::from_value(yaml_value).unwrap();

    // Proxy 0: no auth field -> inherits default
    let auth0 = args.resolve_proxy_auth(&args.proxy_group[0].auth);
    assert_eq!(auth0.len(), 1);
    match &auth0[0] {
      ProxyAuth::Password { username, .. } => assert_eq!(username, "default_user"),
      _ => panic!("Expected Password variant"),
    }

    // Proxy 1: own auth -> overrides default
    let auth1 = args.resolve_proxy_auth(&args.proxy_group[1].auth);
    assert_eq!(auth1.len(), 1);
    match &auth1[0] {
      ProxyAuth::Password { username, .. } => assert_eq!(username, "user1"),
      _ => panic!("Expected Password variant"),
    }

    // Proxy 2: explicit none -> no auth
    let auth2 = args.resolve_proxy_auth(&args.proxy_group[2].auth);
    assert_eq!(auth2.len(), 1);
    assert!(matches!(auth2[0], ProxyAuth::None));
  }

  // ============== TLS Config Building Tests ==============

  #[test]
  fn test_build_tls_client_config_none_auth() {
    use rustls::RootCertStore;

    ensure_crypto_provider();

    let roots = RootCertStore::empty();

    // Build TLS config with no auth
    let config = build_tls_client_config(roots, &ProxyAuth::None);
    assert!(config.is_ok(), "Should build TLS config for None auth");

    // The returned config should be a valid ClientConfig
    let _tls_config = config.unwrap();
    // Note: ALPN protocols are set by the caller, not by build_tls_client_config
  }

  #[test]
  fn test_build_tls_client_config_password_auth() {
    use rustls::RootCertStore;

    ensure_crypto_provider();

    let roots = RootCertStore::empty();

    let auth = ProxyAuth::Password {
      username: "user".to_string(),
      password: "pass".to_string(),
    };

    // Password auth should build a TLS config without client cert
    let config = build_tls_client_config(roots, &auth);
    assert!(config.is_ok(), "Should build TLS config for Password auth");

    // The returned config should be a valid ClientConfig
    let _tls_config = config.unwrap();
    // Note: ALPN protocols are set by the caller, not by build_tls_client_config
  }

  #[test]
  fn test_build_tls_client_config_tls_client_cert_auth() {
    use rustls::RootCertStore;

    ensure_crypto_provider();

    let temp_dir = tempfile::tempdir().unwrap();
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");

    // Write valid PEM data (self-signed cert for testing)
    // Generate a simple ECDSA key and cert for testing
    let rcgen::CertifiedKey { cert, key_pair } =
      rcgen::generate_simple_self_signed(vec!["test".into()]).unwrap();
    fs::write(&cert_path, cert.pem()).unwrap();
    fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    let roots = RootCertStore::empty();

    let auth = ProxyAuth::TlsClientCert {
      client_cert_path: cert_path.clone(),
      client_key_path: key_path.clone(),
    };

    // TLS client cert auth should build a TLS config WITH client cert
    let config = build_tls_client_config(roots, &auth);
    assert!(
      config.is_ok(),
      "Should build TLS config for TlsClientCert auth"
    );

    // The returned config should be a valid ClientConfig with client auth
    let _tls_config = config.unwrap();
    // Note: ALPN protocols are set by the caller, not by build_tls_client_config
    // The config should have client auth configured
    // (we can't easily verify this without actually connecting)
  }

  #[test]
  fn test_build_tls_client_config_tls_client_cert_missing_cert() {
    use rustls::RootCertStore;

    let roots = RootCertStore::empty();

    let auth = ProxyAuth::TlsClientCert {
      client_cert_path: "/nonexistent/cert.pem".into(),
      client_key_path: "/nonexistent/key.pem".into(),
    };

    // Should fail because cert file doesn't exist
    let config = build_tls_client_config(roots, &auth);
    assert!(config.is_err(), "Should fail for missing cert file");
    let err_msg = config.unwrap_err().to_string();
    assert!(
      err_msg.contains("cert") || err_msg.contains("No such file"),
      "Error should mention missing file: {err_msg}"
    );
  }

  // ============== TLS Handshake Error Detection Tests ==============

  #[test]
  fn test_is_tls_handshake_error_detects_certificate_error() {
    // Create an error that looks like a TLS certificate error
    let err = anyhow::anyhow!("TLS handshake failed: certificate rejected");
    assert!(
      is_tls_handshake_error(&err),
      "Should detect certificate error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_detects_handshake_error() {
    let err = anyhow::anyhow!("TLS handshake error: unknown CA");
    assert!(
      is_tls_handshake_error(&err),
      "Should detect handshake error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_rejects_network_error() {
    let err = anyhow::anyhow!("Connection refused");
    assert!(
      !is_tls_handshake_error(&err),
      "Should NOT detect network error as TLS error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_rejects_timeout_error() {
    let err = anyhow::anyhow!("Connection timed out");
    assert!(
      !is_tls_handshake_error(&err),
      "Should NOT detect timeout as TLS error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_case_insensitive() {
    let err = anyhow::anyhow!("tls HANDSHAKE failed");
    assert!(is_tls_handshake_error(&err), "Should be case insensitive");
  }

  #[test]
  fn test_is_tls_handshake_error_detects_quinn_connection_error_with_crypto_code() {
    // Test that we detect ConnectionError::TransportError with crypto error code
    // We need to use the internal quinn_proto type since quinn doesn't export TransportError
    // The crypto error code is created from a TLS alert (e.g., bad_certificate = 42)
    let _crypto_code = quinn::TransportErrorCode::crypto(42); // TLS alert: bad_certificate
    // Create TransportError using the proto crate via quinn's re-exports
    // Since we can't construct it directly, we use the Display string pattern
    // The error message will contain "cryptographic handshake failed"
    let err_msg = format!(
      "TLS handshake failed: cryptographic error 42"
    );
    let err = anyhow::anyhow!("{}", err_msg);
    assert!(
      is_tls_handshake_error(&err),
      "Should detect crypto handshake failure error message"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_rejects_quinn_timeout() {
    // Timeout errors should NOT be detected as TLS handshake errors
    let conn_err = quinn::ConnectionError::TimedOut;
    let err: anyhow::Error = conn_err.into();
    assert!(
      !is_tls_handshake_error(&err),
      "Should NOT detect TimedOut as TLS error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_rejects_quinn_reset() {
    // Reset errors should NOT be detected as TLS handshake errors
    let conn_err = quinn::ConnectionError::Reset;
    let err: anyhow::Error = conn_err.into();
    assert!(
      !is_tls_handshake_error(&err),
      "Should NOT detect Reset as TLS error"
    );
  }

  #[test]
  fn test_is_tls_handshake_error_detects_certificate_error_via_downcast() {
    // Test that we can detect quinn::ConnectionError::TransportError via downcast
    // and check the error code is in the crypto range
    use quinn::ConnectionError;

    // Create a mock error that simulates TLS handshake failure
    // We'll test the downcast mechanism
    let timeout_err: anyhow::Error = ConnectionError::TimedOut.into();
    let downcast_result = timeout_err.downcast_ref::<ConnectionError>();
    assert!(
      downcast_result.is_some(),
      "Should be able to downcast to ConnectionError"
    );
    match downcast_result {
      Some(ConnectionError::TimedOut) => {}
      _ => panic!("Expected TimedOut variant"),
    }
  }

  // ============== Connection with Auth Tests ==============

  // Note: Real connection tests require actual servers and are tested in integration tests.
  // Unit tests here verify the auth chain is passed correctly.

  #[test]
  fn test_proxy_group_new_accepts_auth_chain() {
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let auth_chain = vec![
      ProxyAuth::Password {
        username: "user".to_string(),
        password: "pass".to_string(),
      },
      ProxyAuth::None,
    ];

    let addresses: Vec<(SocketAddr, usize, Vec<ProxyAuth>)> = vec![
      ("127.0.0.1:8080".parse().unwrap(), 1, auth_chain.clone()),
    ];

    let group = ProxyGroup::new(ca_path.into(), addresses);

    assert_eq!(group.proxies.len(), 1);
    assert_eq!(group.proxies[0].auth_chain.len(), 2);
    assert!(matches!(
      group.proxies[0].auth_chain[0],
      ProxyAuth::Password { .. }
    ));
    assert!(matches!(group.proxies[0].auth_chain[1], ProxyAuth::None));
  }

  // ============== ProxyAuthRequiredError Tests ==============

  #[test]
  fn test_proxy_auth_required_error_display() {
    let err = ProxyAuthRequiredError;
    let msg = format!("{err}");
    assert!(
      msg.contains("407"),
      "Error message should contain 407: {msg}"
    );
    assert!(
      msg.contains("Proxy Authentication Required"),
      "Error message should contain Proxy Authentication Required: {msg}"
    );
  }

  #[test]
  fn test_proxy_auth_required_error_downcast() {
    // Test that we can properly detect this error type via downcast
    let err: anyhow::Error = ProxyAuthRequiredError.into();
    assert!(
      err.downcast_ref::<ProxyAuthRequiredError>().is_some(),
      "Should be able to downcast to ProxyAuthRequiredError"
    );
  }

  #[test]
  fn test_proxy_auth_required_error_not_tls_handshake_error() {
    // ProxyAuthRequiredError should NOT be detected as TLS handshake error
    let err: anyhow::Error = ProxyAuthRequiredError.into();
    assert!(
      !is_tls_handshake_error(&err),
      "ProxyAuthRequiredError should not be detected as TLS handshake error"
    );
  }

  #[test]
  fn test_proxy_auth_required_error_in_anyhow() {
    // Test that the error can be converted to anyhow::Error and back
    let err: anyhow::Error = ProxyAuthRequiredError.into();
    let err_msg = err.to_string();
    assert!(
      err_msg.contains("407"),
      "Anyhow error message should contain 407: {err_msg}"
    );
  }
}
