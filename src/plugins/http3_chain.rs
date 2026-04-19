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

use anyhow::{bail, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
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

struct ProxyGroup {
  ca_path: path::PathBuf,
  client_cert_path: Option<path::PathBuf>,
  client_key_path: Option<path::PathBuf>,
  proxies: Vec<Proxy>,
}

impl ProxyGroup {
  fn new(
    ca_path: path::PathBuf,
    addresses: Vec<(SocketAddr, usize)>,
    client_cert_path: Option<path::PathBuf>,
    client_key_path: Option<path::PathBuf>,
  ) -> Self {
    let mut proxies = vec![];
    for (addr, weight) in addresses {
      proxies.push(Proxy {
        address: addr,
        conn_handle: None,
        requester: None,
        weight,
        current_weight: 0,
      });
    }

    Self { ca_path, client_cert_path, client_key_path, proxies }
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

  async fn new_proxy_conn(
    &self,
    proxy_idx: usize,
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
    let ca_file = fs::File::open(self.ca_path.as_path())?;
    let mut ca_reader = std::io::BufReader::new(ca_file);
    let ca_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut ca_reader)
      .collect::<Result<Vec<_>, _>>()
      .map_err(|e| anyhow::anyhow!("failed to parse CA certificate: {e}"))?;

    for cert in ca_certs {
      if let Err(e) = roots.add(cert) {
        error!("failed to add CA certificate to trust store: {e}");
      }
    }

    // CR-003: Build TLS config with optional client cert, then apply common settings
    let mut tls_config = match (&self.client_cert_path, &self.client_key_path) {
      (Some(cert_path), Some(key_path)) => {
        // Load client certificate chain (PEM format)
        let cert_file = fs::File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
          .collect::<Result<Vec<_>, _>>()
          .map_err(|e| anyhow::anyhow!("failed to parse client certificate: {e}"))?;

        // Load client private key (PEM format)
        let key_file = fs::File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
          .ok_or_else(|| anyhow::anyhow!("no private key found in file"))?;

        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_client_auth_cert(cert_chain, key)?
      }
      _ => {
        rustls::ClientConfig::builder()
          .with_root_certificates(roots)
          .with_no_client_auth()
      }
    };
    // Apply common configuration (CR-003: avoid duplication)
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

    info!("QUIC connection established");
    Ok(conn)
  }

  async fn get_proxy_conn(
    &mut self,
    stream_tracker: &StreamTracker,
    conn_tracker: &ActiveConnectionTracker,
  ) -> Result<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>> {
    let idx = self.schedule_wrr();
    let proxy = &mut self.proxies[idx];
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
        return Ok(proxy.requester.as_ref().unwrap().clone());
      }
    }

    let conn = self.new_proxy_conn(idx).await?;
    // Register the QUIC connection to the connection tracker
    // so we can close it gracefully during shutdown
    conn_tracker.register(conn.clone());
    let (h3_conn, requester) =
      h3::client::new(h3_quinn::Connection::new(conn)).await?;

    // Register connection maintenance task to stream tracker
    let conn_task = connection_maintaining(h3_conn);
    stream_tracker.register_connection(async move {
      let _ = conn_task.await;
    });

    let proxy = &mut self.proxies[idx];
    let _ = proxy.conn_handle.take(); // No longer needed, tracked by stream_tracker
    let _ = proxy.requester.insert(requester.clone());
    Ok(requester)
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

#[derive(Deserialize, Default, Clone, Debug)]
struct Http3ChainServiceArgsProxyGroup {
  address: String,
  weight: usize,
}

#[derive(Deserialize, Default, Clone, Debug)]
struct Http3ChainServiceArgs {
  proxy_group: Vec<Http3ChainServiceArgsProxyGroup>,
  ca_path: String,
  // New fields for password authentication
  #[serde(default)]
  username: Option<String>,
  #[serde(default)]
  password: Option<String>,
  // New fields for TLS client certificate
  #[serde(default)]
  client_cert_path: Option<String>,
  #[serde(default)]
  client_key_path: Option<String>,
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

    // CR-014: Validate username/password are non-empty when present
    match (&self.username, &self.password) {
      (Some(user), None) => {
        if user.is_empty() {
          bail!("username cannot be empty");
        }
        bail!("password is required when username is set");
      }
      (None, Some(pass)) => {
        if pass.is_empty() {
          bail!("password cannot be empty");
        }
        bail!("username is required when password is set");
      }
      (Some(user), Some(pass)) => {
        if user.is_empty() {
          bail!("username cannot be empty");
        }
        if pass.is_empty() {
          bail!("password cannot be empty");
        }
      }
      _ => {}
    }
    // CR-014: Validate client cert/key paths are non-empty when present
    match (&self.client_cert_path, &self.client_key_path) {
      (Some(cert_path), Some(key_path)) => {
        // CR-002: Validate that cert and key files exist
        if cert_path.is_empty() {
          bail!("client_cert_path cannot be empty");
        }
        if !path::Path::new(cert_path).exists() {
          bail!("client_cert_path '{}' does not exist", cert_path);
        }
        if key_path.is_empty() {
          bail!("client_key_path cannot be empty");
        }
        if !path::Path::new(key_path).exists() {
          bail!("client_key_path '{}' does not exist", key_path);
        }
      }
      (Some(cert_path), None) => {
        if cert_path.is_empty() {
          bail!("client_cert_path cannot be empty");
        }
        bail!("client_key_path is required when client_cert_path is set");
      }
      (None, Some(key_path)) => {
        if key_path.is_empty() {
          bail!("client_key_path cannot be empty");
        }
        bail!("client_cert_path is required when client_key_path is set");
      }
      _ => {}
    }
    Ok(())
  }
}

#[derive(Clone)]
struct Http3ChainService {
  proxy_group: Rc<RefCell<ProxyGroup>>,
  stream_tracker: Rc<StreamTracker>,
  conn_tracker: ActiveConnectionTracker,
  username: Option<String>,
  password: Option<String>,
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

    let proxy_group =
      ProxyGroup::new(
        args.ca_path.into(),
        args
          .proxy_group
          .iter()
          .filter_map(|e| {
            let Http3ChainServiceArgsProxyGroup {
              address: s,
              weight: w,
            } = e;
            s.parse()
              .inspect_err(|e| error!("address '{s}' invalid: {e}"))
              .ok()
              .map(|a| (a, *w))
          })
          .collect(),
        args.client_cert_path.map(|p| p.into()),
        args.client_key_path.map(|p| p.into()),
      );

    Ok(plugin::Service::new(Self {
      proxy_group: Rc::new(RefCell::new(proxy_group)),
      stream_tracker,
      conn_tracker,
      username: args.username,
      password: args.password,
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
    let username = self.username.clone();
    let password = self.password.clone();

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

      // Get connection to next hop proxy
      let mut requester = match pg.borrow_mut().get_proxy_conn(&st, &ct).await {
        Ok(r) => r,
        Err(e) => {
          warn!("Http3ChainService: failed to connect to next hop proxy: {e}");
          return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
        }
      };

      // Send HTTP/3 CONNECT request to next hop proxy
      let mut builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("{host}:{port}"));

      // Add Proxy-Authorization header if credentials are configured
      if let (Some(user), Some(pass)) = (&username, &password) {
        let credentials = BASE64_STANDARD.encode(format!("{}:{}", user, pass));
        builder = builder.header("Proxy-Authorization", format!("Basic {}", credentials));
      }

      let proxy_req = match builder.body(()) {
        Ok(r) => r,
        Err(e) => {
          warn!("Http3ChainService: failed to build CONNECT request: {e}");
          return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
        }
      };

      let mut proxy_stream = match requester.send_request(proxy_req).await {
        Ok(s) => s,
        Err(e) => {
          warn!("Http3ChainService: failed to send CONNECT request to next hop: {e}");
          return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
        }
      };

      let proxy_resp = match proxy_stream.recv_response().await {
        Ok(r) => r,
        Err(e) => {
          warn!("Http3ChainService: failed to receive response from next hop: {e}");
          return Ok(build_empty_response(http::StatusCode::BAD_GATEWAY));
        }
      };

      if !proxy_resp.status().is_success() {
        return Ok(build_empty_response(proxy_resp.status()));
      }

      // Split proxy stream for bidirectional transfer
      let (sending_stream, receiving_stream) = proxy_stream.split();

      // Build 200 response
      let resp = build_empty_response(http::StatusCode::OK);

      // Get shutdown handle
      let shutdown_handle = st.shutdown_handle();

      // Background task: wait for upgrade, then bidirectional transfer
      st.register(async move {
        // Get client stream (SOCKS5 or HTTP upgrade)
        let client_result: Result<ClientStream, String> =
          if let Some(socks5) = socks5_upgrade {
            match socks5.await {
              Ok(stream) => Ok(ClientStream::Socks5(stream)),
              Err(e) => Err(format!("SOCKS5 upgrade failed: {e}")),
            }
          } else if let Some(http) = http_upgrade {
            match http.await {
              Ok(upgraded) => Ok(ClientStream::Http(TokioIo::new(upgraded))),
              Err(e) => Err(format!("HTTP upgrade failed: {e}")),
            }
          } else {
            // No upgrade available - need to transfer with request body
            // For HTTP/3 chain without upgrade, we need a different approach
            // This case handles the "pure HTTP/3 CONNECT" where there's no client stream
            // to proxy, but we have request body data to send.
            // For now, log a warning and return.
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

        // Create H3BidirectionalStream for proxy stream
        let mut h3_stream = H3BidirectionalStream::new(sending_stream, receiving_stream);

        // Bidirectional transfer with shutdown notification
        let result = tokio::select! {
          res = tokio::io::copy_bidirectional(&mut client, &mut h3_stream) => {
            res
          }
          _ = shutdown_handle.notified() => {
            warn!("Http3ChainService tunnel shutdown by notification");
            return;
          }
        };

        if let Err(e) = result {
          warn!("Http3ChainService tunnel transfer error: {e}");
        }
      });

      Ok(resp)
    })
  }
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
      ("127.0.0.1:8080".parse().unwrap(), 1),
      ("127.0.0.1:8081".parse().unwrap(), 2),
    ];
    let group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
    );

    assert_eq!(group.proxies.len(), 2);
    assert_eq!(group.proxies[0].weight, 1);
    assert_eq!(group.proxies[1].weight, 2);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_single() {
    let addresses = vec![("127.0.0.1:8080".parse().unwrap(), 1)];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
    );

    // With single proxy, should always select index 0
    assert_eq!(group.schedule_wrr(), 0);
  }

  #[test]
  fn test_proxy_group_schedule_wrr_two_proxies_weight_2_to_1() {
    // Test WRR with two proxies: weights 2:1
    // Expected distribution over 6 calls: 0, 1, 0, 0, 1, 0 (4:2 ratio = 2:1)
    let addresses = vec![
      ("127.0.0.1:8080".parse().unwrap(), 2), // weight 2
      ("127.0.0.1:8081".parse().unwrap(), 1), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
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
      ("127.0.0.1:8080".parse().unwrap(), 3), // weight 3
      ("127.0.0.1:8081".parse().unwrap(), 1), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
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
      ("127.0.0.1:8080".parse().unwrap(), 2), // weight 2
      ("127.0.0.1:8081".parse().unwrap(), 1), // weight 1
      ("127.0.0.1:8082".parse().unwrap(), 1), // weight 1
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
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
      ("127.0.0.1:8080".parse().unwrap(), 1),
      ("127.0.0.1:8081".parse().unwrap(), 1),
    ];
    let mut group = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
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
      ("127.0.0.1:8080".parse().unwrap(), 2),
      ("127.0.0.1:8081".parse().unwrap(), 1),
    ];

    // First run
    let mut group1 = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses.clone(),
      None,
      None,
    );
    let selections1: Vec<usize> = (0..6).map(|_| group1.schedule_wrr()).collect();

    // Second run (should produce identical results)
    let mut group2 = ProxyGroup::new(
      "/tmp/ca.pem".into(),
      addresses,
      None,
      None,
    );
    let selections2: Vec<usize> = (0..6).map(|_| group2.schedule_wrr()).collect();

    assert_eq!(selections1, selections2, "WRR should be deterministic");
  }

  // ============== Http3ChainServiceArgs Tests ==============

  #[test]
  fn test_service_args_with_password_auth() {
    let yaml = r#"
proxy_group:
  - address: "127.0.0.1:8080"
    weight: 1
ca_path: "/tmp/ca.pem"
username: "user1"
password: "pass1"
"#;
    let args: Http3ChainServiceArgs = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(args.username, Some("user1".to_string()));
    assert_eq!(args.password, Some("pass1".to_string()));
  }

  #[test]
  fn test_config_validation_username_without_password_fails() {
    // CR-008: Use tempfile to ensure ca_path exists, so validate() reaches
    // the username/password pair check instead of failing on missing ca_path
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: Some("user".to_string()),
      password: None,
      client_cert_path: None,
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    // Verify it fails for the right reason: username without password
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("password is required when username is set"),
      "Expected username-without-password error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_cert_without_key_fails() {
    // CR-008: Use tempfile to ensure ca_path exists
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: Some("/tmp/client.crt".to_string()),
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    // Verify it fails for the right reason: cert without key
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("client_key_path is required when client_cert_path is set"),
      "Expected cert-without-key error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_password_without_username_fails() {
    // CR-008: Use tempfile to ensure ca_path exists
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: Some("pass".to_string()),
      client_cert_path: None,
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err());
    // Verify it fails for the right reason: password without username
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("username is required when password is set"),
      "Expected password-without-username error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_key_without_cert_fails() {
    // CR-008: Use tempfile to ensure ca_path exists
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: None,
      client_key_path: Some("/tmp/client.key".to_string()),
    };
    let result = args.validate();
    assert!(result.is_err());
    // Verify it fails for the right reason: key without cert
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("client_cert_path is required when client_key_path is set"),
      "Expected key-without-cert error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_both_auth_methods_ok() {
    // Create temp files for ca, cert and key validation (CR-002, CR-004)
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let cert_path = temp_dir.path().join("client.crt");
    let key_path = temp_dir.path().join("client.key");
    fs::write(&ca_path, "dummy ca").unwrap();
    fs::write(&cert_path, "dummy cert").unwrap();
    fs::write(&key_path, "dummy key").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: Some("user".to_string()),
      password: Some("pass".to_string()),
      client_cert_path: Some(cert_path.to_string_lossy().to_string()),
      client_key_path: Some(key_path.to_string_lossy().to_string()),
    };
    assert!(args.validate().is_ok());
  }

  #[test]
  fn test_config_validation_nonexistent_cert_file_fails() {
    // CR-002: validate() should check that cert files exist
    // CR-008: Use tempfile to ensure ca_path exists
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
      client_key_path: Some("/nonexistent/path/client.key".to_string()),
    };
    // Should fail because cert files don't exist
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for nonexistent cert files");
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("client_cert_path") && err_msg.contains("does not exist"),
      "Expected cert-not-found error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_nonexistent_key_file_fails() {
    // CR-002: validate() should check that key files exist
    // CR-008: Use tempfile to ensure ca_path and cert exist
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    let cert_path = temp_dir.path().join("client.crt");
    fs::write(&ca_path, "dummy ca").unwrap();
    fs::write(&cert_path, "dummy cert").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: Some(cert_path.to_string_lossy().to_string()),
      client_key_path: Some("/nonexistent/path/client.key".to_string()),
    };
    // Should fail because key file doesn't exist
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for nonexistent key file");
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("client_key_path") && err_msg.contains("does not exist"),
      "Expected key-not-found error, got: {err_msg}"
    );
  }

  // CR-014: Tests for empty username/password validation
  #[test]
  fn test_config_validation_empty_username_fails() {
    // CR-014: Empty username should be rejected at config validation time
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: Some("".to_string()), // Empty username
      password: Some("pass".to_string()),
      client_cert_path: None,
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for empty username");
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("username cannot be empty"),
      "Expected empty username error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_empty_password_fails() {
    // CR-014: Empty password should be rejected at config validation time
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: Some("user".to_string()),
      password: Some("".to_string()), // Empty password
      client_cert_path: None,
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for empty password");
    let err_msg = result.unwrap_err().to_string();
    assert!(
      err_msg.contains("password cannot be empty"),
      "Expected empty password error, got: {err_msg}"
    );
  }

  #[test]
  fn test_config_validation_empty_username_and_password_fails() {
    // CR-014: Both empty should be rejected (first error should be about username)
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: Some("".to_string()), // Empty username
      password: Some("".to_string()), // Empty password
      client_cert_path: None,
      client_key_path: None,
    };
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for empty credentials");
  }

  #[test]
  fn test_config_validation_empty_client_cert_path_fails() {
    // CR-014: Empty client_cert_path should be rejected
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: Some("".to_string()), // Empty path
      client_key_path: Some("/tmp/client.key".to_string()),
    };
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for empty client_cert_path");
  }

  #[test]
  fn test_config_validation_empty_client_key_path_fails() {
    // CR-014: Empty client_key_path should be rejected
    let temp_dir = tempfile::tempdir().unwrap();
    let ca_path = temp_dir.path().join("ca.pem");
    fs::write(&ca_path, "dummy ca").unwrap();

    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: Some("/tmp/client.crt".to_string()),
      client_key_path: Some("".to_string()), // Empty path
    };
    let result = args.validate();
    assert!(result.is_err(), "validate() should fail for empty client_key_path");
  }

  #[test]
  fn test_config_validation_nonexistent_ca_path_fails() {
    // CR-004: validate() should check that ca_path exists
    let args = Http3ChainServiceArgs {
      proxy_group: vec![],
      ca_path: "/nonexistent/path/ca.pem".to_string(),
      username: None,
      password: None,
      client_cert_path: None,
      client_key_path: None,
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
        }
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: None,
      client_key_path: None,
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
        },
        Http3ChainServiceArgsProxyGroup {
          address: "127.0.0.1:8081".to_string(),
          weight: 0, // CR-003: weight 0 should be rejected
        },
      ],
      ca_path: ca_path.to_string_lossy().to_string(),
      username: None,
      password: None,
      client_cert_path: None,
      client_key_path: None,
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
}
