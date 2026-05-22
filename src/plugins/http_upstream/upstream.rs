use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h3::client as h3_cli;
use http::Uri;
use hyper::client::conn::http1;
use hyper_util::client::legacy::connect::Connected;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Service;
use tracing::info;

use crate::http_utils::RequestBody;
use crate::tracker::StreamTracker;
use super::config::{
  Protocol, QuicResolved,
 UserPasswordCredential,
  build_root_cert_store,
};
use super::error::{
  UpstreamError, classify_connect_error, classify_quic_error,
  classify_tls_handshake_error, DnsResolveError,
};

// ============================================================================
// WRR Scheduling
// ============================================================================
// Proxied Connection Wrapper
// ============================================================================

/// Wrapper that marks a connection as proxied (`Connected::proxy(true)`),
/// so hyper sends absolute-form URIs and pools by connected address.
pub(crate) struct Proxied<T>(pub(crate) T);

impl<T: hyper::rt::Read + Unpin> hyper::rt::Read for Proxied<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: hyper::rt::ReadBufCursor<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
  }
}

impl<T: hyper::rt::Write + Unpin> hyper::rt::Write for Proxied<T> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_flush(cx)
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
  }

  fn is_write_vectored(&self) -> bool {
    self.0.is_write_vectored()
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    bufs: &[std::io::IoSlice<'_>],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
  }
}

impl<T: hyper_util::client::legacy::connect::Connection> hyper_util::client::legacy::connect::Connection for Proxied<T> {
  fn connected(&self) -> Connected {
    self.0.connected().proxy(true)
  }
}

/// Newtype wrapper for TlsStream so we can implement Connection for it.
/// Proxied<TokioIo<TlsConn>> will then have both Read/Write and Connection.
pub(crate) struct TlsConn(pub(crate) tokio_rustls::client::TlsStream<tokio::net::TcpStream>);

impl AsyncRead for TlsConn {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
  }
}

impl AsyncWrite for TlsConn {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_flush(cx)
  }

  fn poll_shutdown(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
  }
}

impl hyper_util::client::legacy::connect::Connection for TlsConn {
  fn connected(&self) -> Connected {
    Connected::new()
  }
}

// ============================================================================
// Custom Connectors for Chain Mode
// ============================================================================

/// Connects to a pre-configured upstream proxy address via plain TCP.
/// Ignores the URI and always connects to `addr`. Returns `Proxied` so
/// hyper sends absolute-form URI and pools by the connected address.
#[derive(Clone)]
pub(crate) struct UpstreamConnector {
  addr: String,
  connect_timeout: Duration,
}

impl UpstreamConnector {
  pub(crate) fn new(addr: String, connect_timeout: Duration) -> Self {
    Self { addr, connect_timeout }
  }
}

impl Service<Uri> for UpstreamConnector {
  type Response = Proxied<TokioIo<tokio::net::TcpStream>>;
  type Error = std::io::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, _: Uri) -> Self::Future {
    let addr_str = self.addr.clone();
    let timeout = self.connect_timeout;
    Box::pin(async move {
      let addr = resolve_address(&addr_str)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
      let stream = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(addr),
      )
      .await
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
      Ok(Proxied(TokioIo::new(stream)))
    })
  }
}

/// Connects to a pre-configured upstream proxy address via TLS.
/// Same as `UpstreamConnector` but wraps the TCP stream with a TLS handshake.
#[derive(Clone)]
pub(crate) struct TlsUpstreamConnector {
  inner: UpstreamConnector,
  tls_config: Arc<rustls::ClientConfig>,
  hostname: String,
  tls_handshake_timeout: Duration,
}

impl TlsUpstreamConnector {
  pub(crate) fn new(
    inner: UpstreamConnector,
    tls_config: Arc<rustls::ClientConfig>,
    hostname: String,
    tls_handshake_timeout: Duration,
  ) -> Self {
    Self { inner, tls_config, hostname, tls_handshake_timeout }
  }
}

impl Service<Uri> for TlsUpstreamConnector {
  type Response = Proxied<TokioIo<TlsConn>>;
  type Error = std::io::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

  fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, uri: Uri) -> Self::Future {
    let mut inner = self.inner.clone();
    let tls_config = self.tls_config.clone();
    let hostname = self.hostname.clone();
    let tls_handshake_timeout = self.tls_handshake_timeout;
    Box::pin(async move {
      let Proxied(tcp_io) = inner.call(uri).await?;
      let server_name = rustls::pki_types::ServerName::try_from(hostname)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
      let connector = tokio_rustls::TlsConnector::from(tls_config);
      let tcp_stream = tcp_io.into_inner();
      let tls_stream = tokio::time::timeout(
        tls_handshake_timeout,
        connector.connect(server_name, tcp_stream),
      )
      .await
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
      Ok(Proxied(TokioIo::new(TlsConn(tls_stream))))
    })
  }
}

// ============================================================================
// WRR Scheduling
// ============================================================================

pub(crate) fn schedule_wrr(addresses: &[super::config::ResolvedAddress]) -> Option<usize> {
  if addresses.is_empty() {
    return None;
  }
  let total = addresses.iter().fold(0, |t, a| t + a.weight) as isize;
  let mut selected_idx = 0usize;
  let mut selected_weight = 0isize;
  for (i, a) in addresses.iter().enumerate() {
    let new_cw = a.current_weight.get() + a.weight as isize;
    a.current_weight.set(new_cw);
    if new_cw > selected_weight {
      selected_weight = new_cw;
      selected_idx = i;
    }
  }
  let new_cw = addresses[selected_idx].current_weight.get() - total;
  addresses[selected_idx].current_weight.set(new_cw);
  Some(selected_idx)
}

// ============================================================================
// Per-Address HTTP/HTTPS Client (hyper::Client with custom connectors)
// ============================================================================

// Note: Connection pooling is handled by hyper::Client's built-in pool,
// keyed by the connected address (via Proxied's proxy(true) Connection impl).

// ============================================================================
// Per-Address H3 Connection State
// ============================================================================

pub(crate) struct H3AddressState {
  pub(crate) quinn_conn: Option<quinn::Connection>,
  pub(crate) send_request: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

impl H3AddressState {
  pub(crate) fn new() -> Self {
    Self { quinn_conn: None, send_request: None }
  }

  pub(crate) fn is_alive(&self) -> bool {
    self.quinn_conn
      .as_ref()
      .map(|c| c.close_reason().is_none())
      .unwrap_or(false)
      && self.send_request.is_some()
  }
}

// ============================================================================
// Rewind Wrapper
// ============================================================================

pub(crate) struct Rewind<T> {
  inner: T,
  prefix: Option<Bytes>,
}

impl<T> Rewind<T> {
  pub(crate) fn new(inner: T, prefix: Option<Bytes>) -> Self {
    Self { inner, prefix }
  }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for Rewind<T> {
  fn poll_read(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    if let Some(ref mut prefix) = self.prefix {
      if !prefix.is_empty() {
        let n = std::cmp::min(buf.remaining(), prefix.len());
        if n > 0 {
          buf.put_slice(&prefix[..n]);
          *prefix = prefix.slice(n..);
          if prefix.is_empty() {
            self.prefix = None;
          }
          return std::task::Poll::Ready(Ok(()));
        }
        self.prefix = None;
      }
    }
    std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Rewind<T> {
  fn poll_write(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
  ) -> std::task::Poll<std::io::Result<usize>> {
    std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<std::io::Result<()>> {
    std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

// ============================================================================
// Connect Result
// ============================================================================

pub(crate) struct ConnectResult {
  pub(crate) transport: TunnelTransport,
  pub(crate) upstream_addr: Option<std::net::SocketAddr>,
  pub(crate) upstream_proxy_status: Option<http::HeaderValue>,
  pub(crate) tunnel_idle_timeout: Duration,
}

// ============================================================================
// Tunnel Transport
// ============================================================================

pub(crate) enum TunnelTransport {
  Tcp(Box<dyn crate::stream::Io>),
  Http3(crate::h3_stream::H3ClientBidiStream),
}

// ============================================================================
// Chain Transport (hyper::Client-based for HTTP/HTTPS, SendRequest for H3)
// ============================================================================

pub(crate) enum Transport {
  Direct {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, RequestBody>,
  },
  Http {
    client: Client<UpstreamConnector, RequestBody>,
    user: UserPasswordCredential,
  },
  Https {
    client: Client<TlsUpstreamConnector, RequestBody>,
    user: UserPasswordCredential,
  },
  Http3 {
    send_request: h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
    user: UserPasswordCredential,
  },
}

// ============================================================================
// Upstream Entry (config + clients per upstream)
// ============================================================================

pub(crate) struct UpstreamEntry {
  pub(crate) addresses: Vec<super::config::ResolvedAddress>,
  // Direct mode only: connect timeout and tunnel idle timeout.
  // Chain mode reads per-address timeouts from Protocol variants.
  pub(crate) connect_timeout: Option<Duration>,
  pub(crate) tunnel_idle_timeout: Option<Duration>,
  // Direct mode client (None for chain upstreams)
  pub(crate) direct_http_client: Option<Client<hyper_util::client::legacy::connect::HttpConnector, RequestBody>>,
  // Chain mode: per-address clients, keyed by address string
  pub(crate) http_clients: HashMap<String, Client<UpstreamConnector, RequestBody>>,
  pub(crate) https_clients: HashMap<String, Client<TlsUpstreamConnector, RequestBody>>,
  pub(crate) h3_pools: HashMap<String, Rc<RefCell<H3AddressState>>>,
}

// ============================================================================
// Upstream Registry
// ============================================================================

pub(crate) struct UpstreamRegistry {
  pub(crate) resolved: HashMap<String, UpstreamEntry>,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  tracker: Rc<StreamTracker>,
}

impl UpstreamRegistry {
  pub(crate) fn new(
    config: &super::config::HttpUpstreamPluginConfig,
    tracker: Rc<StreamTracker>,
  ) -> Result<Self> {
    let resolved_config = super::config::resolve_chain_config(config)?;

    let tls_config = if let Some(ref certs) = config.certificates {
      certs.validate()?;
      let roots = build_root_cert_store(certs.server_ca_path.as_deref())?;
      let ccc = super::config::ClientCertCredential {
        cert_path: certs.client_cert_path.as_ref().map(Into::into),
        key_path: certs.client_key_path.as_ref().map(Into::into),
      };

      let mut https_config = ccc.build_tls_config(roots)?;
      https_config.alpn_protocols = vec![b"http/1.1".to_vec()];
      https_config.key_log = Arc::new(rustls::KeyLogFile::new());

      Some(Arc::new(https_config))
    } else {
      None
    };

    let mut resolved: HashMap<String, UpstreamEntry> = HashMap::new();

    for (upstream_name, upstream) in resolved_config {
      if upstream.addresses.is_empty() {
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.set_connect_timeout(Some(upstream.connect_timeout));
        let mut builder = Client::builder(hyper_util::rt::TokioExecutor::new());
        builder.pool_max_idle_per_host(upstream.pool_config.max_idle_per_host);
        builder.pool_idle_timeout(upstream.pool_config.idle_timeout);
        let client = builder.build(connector);

        resolved.insert(upstream_name, UpstreamEntry {
          addresses: upstream.addresses,
          connect_timeout: Some(upstream.connect_timeout),
          tunnel_idle_timeout: Some(upstream.tunnel_idle_timeout),
          direct_http_client: Some(client),
          http_clients: HashMap::new(),
          https_clients: HashMap::new(),
          h3_pools: HashMap::new(),
        });
        continue;
      }

      let mut http_clients: HashMap<String, Client<UpstreamConnector, RequestBody>> = HashMap::new();
      let mut https_clients: HashMap<String, Client<TlsUpstreamConnector, RequestBody>> = HashMap::new();
      let mut h3_pools: HashMap<String, Rc<RefCell<H3AddressState>>> = HashMap::new();

      for addr in &upstream.addresses {
        match &addr.protocol {
          Protocol::Http { connect_timeout, .. } => {
            let connector = UpstreamConnector::new(addr.address.clone(), *connect_timeout);
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
              .pool_max_idle_per_host(upstream.pool_config.max_idle_per_host)
              .pool_idle_timeout(upstream.pool_config.idle_timeout)
              .build(connector);
            http_clients.insert(addr.address.clone(), client);
          }
          Protocol::Https { connect_timeout, tls_handshake_timeout, .. } => {
            let tls = tls_config.clone()
              .ok_or_else(|| anyhow!("no TLS configuration for HTTPS upstream '{upstream_name}'"))?;
            let host = addr.hostname.as_deref().unwrap_or_else(|| {
              addr.address.split_at(addr.address.rfind(':').unwrap_or(addr.address.len())).0
            });
            let inner = UpstreamConnector::new(addr.address.clone(), *connect_timeout);
            let connector = TlsUpstreamConnector::new(inner, tls, host.to_string(), *tls_handshake_timeout);
            let client = Client::builder(hyper_util::rt::TokioExecutor::new())
              .pool_max_idle_per_host(upstream.pool_config.max_idle_per_host)
              .pool_idle_timeout(upstream.pool_config.idle_timeout)
              .build(connector);
            https_clients.insert(addr.address.clone(), client);
          }
          Protocol::Http3 { .. } => {
            h3_pools.insert(addr.address.clone(), Rc::new(RefCell::new(H3AddressState::new())));
          }
        }
      }

      resolved.insert(upstream_name, UpstreamEntry {
        addresses: upstream.addresses,
        connect_timeout: None,
        tunnel_idle_timeout: None,
        direct_http_client: None,
        http_clients,
        https_clients,
        h3_pools,
      });
    }

    Ok(Self { resolved, tls_config, tracker })
  }

  pub(crate) async fn get_transport(
    &self,
    upstream_name: &str,
  ) -> Result<Transport, UpstreamError> {
    let upstream = self.resolved.get(upstream_name)
      .ok_or_else(|| UpstreamError::ProxyInternalError(
        format!("upstream '{upstream_name}' not found"),
      ))?;

    // Direct mode: return the direct client
    if upstream.addresses.is_empty() {
      let client = upstream.direct_http_client
        .as_ref()
        .ok_or_else(|| UpstreamError::ProxyInternalError(
          format!("no direct client for upstream '{upstream_name}'"),
        ))?
        .clone();
      return Ok(Transport::Direct { client });
    }

    // Chain mode: WRR select address
    let idx = schedule_wrr(&upstream.addresses)
      .ok_or_else(|| UpstreamError::ProxyInternalError(
        format!("upstream '{upstream_name}' has no addresses"),
      ))?;
    let resolved = &upstream.addresses[idx];
    let address = resolved.address.clone();
    let hostname = resolved.hostname.clone();

    let user = resolved.user.clone();

    match &resolved.protocol {
      Protocol::Http { .. } => {
        let client = upstream.http_clients.get(&address)
          .ok_or_else(|| UpstreamError::ProxyInternalError(
            format!("no HTTP client for {address}"),
          ))?
          .clone();

        Ok(Transport::Http {
          client,
          user,
        })
      }
      Protocol::Https { .. } => {
        let client = upstream.https_clients.get(&address)
          .ok_or_else(|| UpstreamError::ProxyInternalError(
            format!("no HTTPS client for {address}"),
          ))?
          .clone();

        Ok(Transport::Https {
          client,
          user,
        })
      }
      Protocol::Http3 { quic, tls_handshake_timeout, .. } => {
        let tls_config = self.tls_config.clone()
          .ok_or_else(|| UpstreamError::TlsCertificateError(
            "no TLS configuration for HTTP/3 upstream".into(),
          ))?;

        let h3_state = upstream.h3_pools.get(&address)
          .ok_or_else(|| UpstreamError::ProxyInternalError(
            format!("no H3 pool for {address}"),
          ))?
          .clone();

        if h3_state.borrow().is_alive() {
          let sr = h3_state.borrow().send_request.clone().unwrap();
          return Ok(Transport::Http3 {
            send_request: sr,
            user,
          });
        }

        let (quinn_conn, sr) = establish_h3_connection(
          &address, hostname.as_deref(), quic, &tls_config, &self.tracker, *tls_handshake_timeout,
        ).await?;

        let mut state = h3_state.borrow_mut();
        state.quinn_conn = Some(quinn_conn);
        state.send_request = Some(sr.clone());

        Ok(Transport::Http3 {
          send_request: sr,
          user,
        })
      }
    }
  }

  pub(crate) async fn connect_for_tunnel(
    &self,
    upstream_name: &str,
    target: &str,
  ) -> Result<ConnectResult, UpstreamError> {
    let upstream = self.resolved.get(upstream_name)
      .ok_or_else(|| UpstreamError::ProxyInternalError(
        format!("upstream '{upstream_name}' not found"),
      ))?;

    // Direct mode
    if upstream.addresses.is_empty() {
      let connect_timeout = upstream.connect_timeout
        .expect("direct upstream must have connect_timeout");
      let tunnel_idle_timeout = upstream.tunnel_idle_timeout
        .expect("direct upstream must have tunnel_idle_timeout");

      let stream = tokio::time::timeout(
        connect_timeout,
        tokio::net::TcpStream::connect(target),
      )
      .await
      .map_err(|_| UpstreamError::ConnectionTimeout(
        format!("direct connect to {target} timed out"),
      ))?
      .map_err(|e| classify_connect_error(e.into()))?;

      let upstream_addr = stream.peer_addr().ok();

      return Ok(ConnectResult {
        transport: TunnelTransport::Tcp(Box::new(stream)),
        upstream_addr,
        upstream_proxy_status: None,
        tunnel_idle_timeout,
      });
    }

    // Chain mode: WRR select address
    let idx = schedule_wrr(&upstream.addresses)
      .ok_or_else(|| UpstreamError::ProxyInternalError(
        format!("upstream '{upstream_name}' has no addresses"),
      ))?;
    let resolved = &upstream.addresses[idx];
    let address = resolved.address.clone();
    let hostname = resolved.hostname.clone();
    let user = resolved.user.clone();
    let tunnel_idle_timeout = resolved.tunnel_idle_timeout;

    match &resolved.protocol {
      Protocol::Http { connect_timeout, .. } => {
        let addr = resolve_address(&address).map_err(|e| classify_connect_error(e))?;
        let stream = tokio::time::timeout(
          *connect_timeout,
          tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| UpstreamError::ConnectionTimeout(
          format!("TCP connect to {address} timed out"),
        ))?
        .map_err(|e| classify_connect_error(e.into()))?;

        let upstream_addr = stream.peer_addr().ok();

        let io = TokioIo::new(stream);
        let (mut sr, conn) = http1::handshake(io).await
          .map_err(|e| UpstreamError::ProxyInternalError(
            format!("HTTP/1.1 handshake failed: {e}"),
          ))?;

        let req = build_connect_request(target, &user);
        let resp = sr.send_request(req).await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        let upstream_proxy_status = resp.headers()
          .get(http::header::HeaderName::from_static("proxy-status"))
          .cloned();

        if resp.status() != http::StatusCode::OK {
          return Err(UpstreamError::UpstreamConnectError {
            status: resp.status(),
            upstream_proxy_status,
          });
        }

        let parts = conn.without_shutdown().await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        Ok(ConnectResult {
          transport: TunnelTransport::Tcp(Box::new(Rewind::new(parts.io.into_inner(), Some(parts.read_buf)))),
          upstream_addr,
          upstream_proxy_status,
          tunnel_idle_timeout,
        })
      }
      Protocol::Https { connect_timeout, tls_handshake_timeout, .. } => {
        let tls_config = self.tls_config.clone()
          .ok_or_else(|| UpstreamError::TlsCertificateError(
            "no TLS configuration for HTTPS upstream".into(),
          ))?;

        let addr = resolve_address(&address).map_err(|e| classify_connect_error(e))?;
        let stream = tokio::time::timeout(
          *connect_timeout,
          tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| UpstreamError::ConnectionTimeout(
          format!("TCP connect to {address} timed out"),
        ))?
        .map_err(|e| classify_connect_error(e.into()))?;

        let upstream_addr = stream.peer_addr().ok();

        let host: &str = hostname.as_deref().unwrap_or_else(|| {
          address.split_at(address.rfind(':').unwrap_or(address.len())).0
        });
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
          .map_err(|e| UpstreamError::DnsError(format!("invalid server name: {e}")))?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let tls_stream = tokio::time::timeout(
          *tls_handshake_timeout,
          connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| UpstreamError::ConnectionTimeout(
          format!("TLS handshake with {address} timed out"),
        ))?
        .map_err(|e| classify_tls_handshake_error(e.into()))?;

        let io = TokioIo::new(tls_stream);
        let (mut sr, conn) = http1::handshake(io).await
          .map_err(|e| UpstreamError::ProxyInternalError(
            format!("HTTPS/1.1 handshake failed: {e}"),
          ))?;

        let req = build_connect_request(target, &user);
        let resp = sr.send_request(req).await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        let upstream_proxy_status = resp.headers()
          .get(http::header::HeaderName::from_static("proxy-status"))
          .cloned();

        if resp.status() != http::StatusCode::OK {
          return Err(UpstreamError::UpstreamConnectError {
            status: resp.status(),
            upstream_proxy_status,
          });
        }

        let parts = conn.without_shutdown().await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        Ok(ConnectResult {
          transport: TunnelTransport::Tcp(Box::new(Rewind::new(parts.io.into_inner(), Some(parts.read_buf)))),
          upstream_addr,
          upstream_proxy_status,
          tunnel_idle_timeout,
        })
      }
      Protocol::Http3 { quic, tls_handshake_timeout, .. } => {
        let tls_config = self.tls_config.clone()
          .ok_or_else(|| UpstreamError::TlsCertificateError(
            "no TLS configuration for HTTP/3 upstream".into(),
          ))?;

        let h3_state = upstream.h3_pools.get(&address)
          .ok_or_else(|| UpstreamError::ProxyInternalError(
            format!("no H3 pool for {address}"),
          ))?
          .clone();

        let mut send_request = if h3_state.borrow().is_alive() {
          h3_state.borrow().send_request.clone().unwrap()
        } else {
          let (quinn_conn, sr) = establish_h3_connection(
            &address, hostname.as_deref(), quic, &tls_config, &self.tracker, *tls_handshake_timeout,
          ).await?;
          let mut state = h3_state.borrow_mut();
          state.quinn_conn = Some(quinn_conn);
          state.send_request = Some(sr.clone());
          sr
        };

        let mut req = http::Request::builder()
          .method(http::Method::CONNECT)
          .uri(target)
          .body(())
          .map_err(|e| UpstreamError::ProxyInternalError(e.to_string()))?;

        user.apply(&mut req);

        let mut stream = send_request.send_request(req).await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        let resp = stream.recv_response().await
          .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

        let upstream_proxy_status = resp.headers()
          .get(http::header::HeaderName::from_static("proxy-status"))
          .cloned();

        if resp.status() != http::StatusCode::OK {
          return Err(UpstreamError::UpstreamConnectError {
            status: resp.status(),
            upstream_proxy_status,
          });
        }

        let (sending_stream, receiving_stream) = stream.split();
        Ok(ConnectResult {
          transport: TunnelTransport::Http3(
            crate::h3_stream::H3ClientBidiStream::new(sending_stream, receiving_stream),
          ),
          upstream_addr: None,
          upstream_proxy_status,
          tunnel_idle_timeout,
        })
      }
    }
  }

  pub(crate) fn close_all(&self) {
    for entry in self.resolved.values() {
      for state in entry.h3_pools.values() {
        if let Some(ref conn) = state.borrow().quinn_conn {
          conn.close(quinn::VarInt::from_u32(0x100), b"shutdown");
        }
      }
    }
  }
}

// ============================================================================
// Connection Establishment (H3 only; HTTP/HTTPS handled by hyper::Client)
// ============================================================================

async fn establish_h3_connection(
  address: &str,
  hostname: Option<&str>,
  quic: &QuicResolved,
  tls_config: &rustls::ClientConfig,
  tracker: &Rc<StreamTracker>,
  tls_handshake_timeout: Duration,
) -> Result<(quinn::Connection, h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>), UpstreamError> {
  let quinn_conn = create_quic_connection(address, hostname, quic, tls_config, tls_handshake_timeout).await?;

  let (mut h3_conn, send_request) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone()))
      .await
      .map_err(|e| UpstreamError::ProxyInternalError(
        format!("H3 connection setup to {address} failed: {e}"),
      ))?;

  tracker.register_connection(async move {
    let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
  });

  info!("HTTP/3 connection established to {address}");
  Ok((quinn_conn, send_request))
}

async fn create_quic_connection(
  address: &str,
  hostname: Option<&str>,
  quic: &QuicResolved,
  tls_config: &rustls::ClientConfig,
  tls_handshake_timeout: Duration,
) -> Result<quinn::Connection, UpstreamError> {
  let mut tls_config = tls_config.clone();
  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![b"h3".to_vec()];

  let mut cli_endpoint =
    quinn::Endpoint::client("[::]:0".parse().unwrap())
      .map_err(|e| UpstreamError::ProxyInternalError(
        format!("failed to create QUIC endpoint: {e}"),
      ))?;

  let mut cli_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
      .map_err(|e| UpstreamError::TlsProtocolError(
        format!("QUIC TLS config error: {e}"),
      ))?,
  ));

  let mut transport = quinn::TransportConfig::default();
  transport.keep_alive_interval(Some(quic.keep_alive_interval));
  if let Some(idle) = quic.max_idle_timeout {
    let ms = u64::try_from(idle.as_millis())
      .map_err(|_| UpstreamError::ProxyInternalError("quic max_idle_timeout too large".into()))?;
    transport.max_idle_timeout(Some(
      quinn::VarInt::from_u64(ms)
        .context("quic max_idle_timeout overflow")
        .map_err(|e| UpstreamError::ProxyInternalError(e.to_string()))?
        .into(),
    ));
  }
  if let Some(v) = quic.max_concurrent_bidi_streams {
    transport.max_concurrent_bidi_streams(
      quinn::VarInt::from_u64(v).context("max_concurrent_bidi_streams overflow")
        .map_err(|e| UpstreamError::ProxyInternalError(e.to_string()))?,
    );
  }
  if let Some(v) = quic.initial_mtu {
    transport.initial_mtu(v);
  }
  if let Some(v) = quic.send_window {
    transport.send_window(v);
  }
  if let Some(v) = quic.receive_window {
    transport.receive_window(
      quinn::VarInt::from_u64(v).context("receive_window overflow")
        .map_err(|e| UpstreamError::ProxyInternalError(e.to_string()))?,
    );
  }
  cli_config.transport_config(Arc::new(transport));

  cli_endpoint.set_default_client_config(cli_config);

  let addr = resolve_address(address).map_err(|e| classify_quic_error(e))?;
  let host: &str = hostname.unwrap_or_else(|| {
    address.split_at(address.rfind(':').unwrap_or(address.len())).0
  });
  let connecting = cli_endpoint
    .connect(addr, host)
    .map_err(|e| classify_quic_error(e.into()))?;
  let conn = tokio::time::timeout(
    tls_handshake_timeout,
    async { connecting.await.map_err(|e| classify_quic_error(e.into())) },
  )
  .await
  .map_err(|_| UpstreamError::ConnectionTimeout(
    format!("QUIC handshake with {address} timed out"),
  ))??;

  info!("QUIC connection established to {address}");
  Ok(conn)
}

// ============================================================================
// Helpers
// ============================================================================

pub(crate) fn resolve_address(s: &str) -> Result<SocketAddr> {
  s.parse()
    .or_else(|_| {
      std::net::ToSocketAddrs::to_socket_addrs(s)
        .map_err(|e| {
          anyhow::Error::from(DnsResolveError(e))
            .context(format!("address '{s}' is neither IP:port nor resolvable hostname"))
        })
        .and_then(|mut addrs| {
          addrs.next().ok_or_else(|| anyhow!("address '{s}' resolved to no addresses"))
        })
    })
    .with_context(|| format!("address '{s}'"))
}

fn build_connect_request(
  target: &str,
  user: &UserPasswordCredential,
) -> http::Request<RequestBody> {
  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(target)
    .body(())
    .expect("building CONNECT request should not fail");
  user.apply(&mut req);
  let empty = http_body_util::Empty::new();
  let wrapped = crate::http_utils::BytesBufBodyWrapper::new(empty);
  let body = RequestBody::new(wrapped);
  // Rebuild with proper body
  let (parts, _) = req.into_parts();
  http::Request::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
  use super::*;
  use super::super::config::{Protocol, QuicResolved};

  #[test]
  fn test_schedule_wrr_single_address() {
    let addresses = vec![super::super::config::ResolvedAddress {
      address: "a:1".into(),
      hostname: None,
      weight: 1,
      current_weight: std::cell::Cell::new(0),
      protocol: Protocol::Http {
        connect_timeout: Duration::from_secs(10),
      },
      tunnel_idle_timeout: Duration::from_secs(60),
      user: UserPasswordCredential::none(),
    }];
    assert_eq!(schedule_wrr(&addresses), Some(0));
  }

  #[test]
  fn test_schedule_wrr_weighted() {
    let addresses = vec![
      super::super::config::ResolvedAddress {
        address: "a:1".into(),
        hostname: None,
        weight: 3,
        current_weight: std::cell::Cell::new(0),
        protocol: Protocol::Http {
          connect_timeout: Duration::from_secs(10),
        },
        tunnel_idle_timeout: Duration::from_secs(60),
        user: UserPasswordCredential::none(),
      },
      super::super::config::ResolvedAddress {
        address: "b:2".into(),
        hostname: None,
        weight: 1,
        current_weight: std::cell::Cell::new(0),
        protocol: Protocol::Http3 {
          tls_handshake_timeout: Duration::from_secs(10),
          quic: QuicResolved {
            max_idle_timeout: None,
            keep_alive_interval: Duration::from_secs(3),
            max_concurrent_bidi_streams: None,
            initial_mtu: None,
            send_window: None,
            receive_window: None,
          },
        },
        tunnel_idle_timeout: Duration::from_secs(60),
        user: UserPasswordCredential::none(),
      },
    ];
    let mut count_a = 0;
    let mut count_b = 0;
    for _ in 0..8 {
      match schedule_wrr(&addresses) {
        Some(0) => count_a += 1,
        Some(1) => count_b += 1,
        _ => panic!("unexpected index"),
      }
    }
    assert_eq!(count_a, 6);
    assert_eq!(count_b, 2);
  }

  #[test]
  fn test_schedule_wrr_empty() {
    let mut addresses: Vec<super::super::config::ResolvedAddress> = vec![];
    assert_eq!(schedule_wrr(&mut addresses), None);
  }

  #[test]
  fn test_resolve_address_ip_port() {
    let addr = resolve_address("127.0.0.1:8080").unwrap();
    assert_eq!(addr.port(), 8080);
  }

  #[test]
  fn test_resolve_address_invalid() {
    assert!(resolve_address("invalid").is_err());
  }
}
