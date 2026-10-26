//! module: plugins::http_upstream::upstream::http
//! responsibility: adapt HTTP/HTTPS proxy transports to the client
//! contract
//! public operations: ProxyConnector, new, TlsProxyConnector,
//! HttpProxyClient, HttpsClient
//! data entities: ProxyConnector, TlsProxyConnector,
//! HttpProxyClient, HttpsClient
//! tests: http_tests.rs

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http::Uri;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tower::Service;
use tracing::warn;

use super::address_resolution::resolve_addresses;
use super::connect_request::build_connect_request;
use super::forward::chain_forward_http;
use super::http_pool::ProxyPool;
use super::protocol::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_connect_error, classify_tls_handshake_error,
};
use crate::plugins::http_upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

fn classify_tcp_connect_error(
  address: &str,
  e: std::io::Error,
) -> UpstreamError {
  if e.kind() == std::io::ErrorKind::TimedOut {
    return UpstreamError::ConnectionTimeout(format!(
      "TCP connect to {address} timed out"
    ));
  }
  classify_connect_error(e.into())
}

// ============================================================================
// Custom Connectors for Chain Mode
// ============================================================================

/// Connects to a pre-configured upstream proxy address.
/// The owning proxy pool defines connection identity; each request
/// retains its absolute-form target URI on the wire.
#[derive(Clone)]
pub(crate) struct ProxyConnector {
  proxy_addr: String,
  connect_timeout: Duration,
  dns_resolve_timeout: Duration,
}

impl ProxyConnector {
  pub(crate) fn new(
    proxy_addr: String,
    connect_timeout: Duration,
    dns_resolve_timeout: Duration,
  ) -> Self {
    Self { proxy_addr, connect_timeout, dns_resolve_timeout }
  }
}

impl Service<Uri> for ProxyConnector {
  type Error = std::io::Error;
  type Future = Pin<
    Box<
      dyn Future<Output = Result<Self::Response, Self::Error>> + Send,
    >,
  >;
  type Response = TokioIo<tokio::net::TcpStream>;

  fn poll_ready(
    &mut self,
    _: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, _uri: Uri) -> Self::Future {
    let proxy_addr = self.proxy_addr.clone();
    let timeout = self.connect_timeout;
    let dns_timeout = self.dns_resolve_timeout;
    Box::pin(async move {
      let addresses = tokio::time::timeout(
        dns_timeout,
        resolve_addresses(&proxy_addr),
      )
      .await
      .map_err(|_| {
        std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          format!("DNS resolve for '{proxy_addr}' timed out"),
        )
      })?
      .map_err(std::io::Error::other)?;
      let stream =
        super::tcp_connect::connect(addresses, timeout).await?;
      Ok(TokioIo::new(stream))
    })
  }
}

/// Connects to a pre-configured upstream proxy address via TLS.
/// Same as `ProxyConnector` but wraps the TCP stream with a TLS
/// handshake to that proxy.
#[derive(Clone)]
pub(crate) struct TlsProxyConnector {
  inner: ProxyConnector,
  tls_config: Arc<rustls::ClientConfig>,
  hostname: String,
  tls_handshake_timeout: Duration,
}

impl TlsProxyConnector {
  pub(crate) fn new(
    inner: ProxyConnector,
    tls_config: Arc<rustls::ClientConfig>,
    hostname: String,
    tls_handshake_timeout: Duration,
  ) -> Self {
    Self { inner, tls_config, hostname, tls_handshake_timeout }
  }
}

impl Service<Uri> for TlsProxyConnector {
  type Error = std::io::Error;
  type Future = Pin<
    Box<
      dyn Future<Output = Result<Self::Response, Self::Error>> + Send,
    >,
  >;
  type Response =
    TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

  fn poll_ready(
    &mut self,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, uri: Uri) -> Self::Future {
    let mut inner = self.inner.clone();
    let tls_config = self.tls_config.clone();
    let hostname = self.hostname.clone();
    let tls_handshake_timeout = self.tls_handshake_timeout;
    Box::pin(async move {
      let tcp_io = inner.call(uri).await?;
      let server_name =
        rustls::pki_types::ServerName::try_from(hostname).map_err(
          |e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
        )?;
      let connector = tokio_rustls::TlsConnector::from(tls_config);
      let tcp_stream = tcp_io.into_inner();
      let tls_stream = tokio::time::timeout(
        tls_handshake_timeout,
        connector.connect(server_name, tcp_stream),
      )
      .await
      .map_err(|_| {
        std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "TLS handshake timed out",
        )
      })??;
      Ok(TokioIo::new(tls_stream))
    })
  }
}

// ============================================================================
// HTTP/HTTPS Forward
// ============================================================================

// ============================================================================
// HTTP Client (cleartext proxy or direct-to-origin)
// ============================================================================

pub(crate) struct HttpProxyClient<C> {
  pub(crate) client: ProxyPool<C>,
  pub(crate) proxy_addr: String,
  pub(crate) connect_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl<C> ClientProtocol for HttpProxyClient<C>
where
  C: tower::Service<Uri, Error = std::io::Error> + Clone,
  C::Response:
    hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let client = self.client.clone();
    let user = self.user.clone();
    Box::pin(async move {
      Ok(
        chain_forward_http(
          client,
          user,
          target,
          req_headers,
          req_body,
          ctx,
        )
        .await,
      )
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let proxy_addr = self.proxy_addr.clone();
    let connect_timeout = self.connect_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    let user = self.user.clone();
    Box::pin(async move {
      let addr = &proxy_addr;

      // Http proxy mode: TCP to proxy + HTTP/1.1 handshake +
      // CONNECT
      let dns_timeout = self.dns_resolve_timeout;
      let resolved =
        tokio::time::timeout(dns_timeout, resolve_addresses(addr))
          .await
          .map_err(|_| {
            UpstreamError::DnsError(format!(
              "DNS resolve for '{addr}' timed out"
            ))
          })?
          .map_err(classify_connect_error)?;
      let stream =
        super::tcp_connect::connect(resolved, connect_timeout)
          .await
          .map_err(|e| classify_tcp_connect_error(addr, e))?;

      let upstream_addr = stream.peer_addr().ok();
      let io = TokioIo::new(stream);
      negotiate_tunnel(
        io,
        target,
        &user,
        tracker,
        upstream_addr,
        tunnel_idle_timeout,
      )
      .await
    })
  }

  fn close(&self) {
    self.client.close();
  }
}

// ============================================================================
// HTTPS Client (TLS to proxy, always proxy mode)
// ============================================================================

pub(crate) struct HttpsClient {
  pub(crate) client: ProxyPool<TlsProxyConnector>,
  pub(crate) proxy_addr: String,
  pub(crate) hostname: String,
  pub(crate) connect_timeout: Duration,
  pub(crate) tls_handshake_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl ClientProtocol for HttpsClient {
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let client = self.client.clone();
    let user = self.user.clone();
    Box::pin(async move {
      Ok(
        chain_forward_http(
          client,
          user,
          target,
          req_headers,
          req_body,
          ctx,
        )
        .await,
      )
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let addr = self.proxy_addr.clone();
    let hostname = self.hostname.clone();
    let connect_timeout = self.connect_timeout;
    let tls_handshake_timeout = self.tls_handshake_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    let user = self.user.clone();
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTPS upstream".into(),
        )
      })?;

      let dns_timeout = self.dns_resolve_timeout;
      let resolved =
        tokio::time::timeout(dns_timeout, resolve_addresses(&addr))
          .await
          .map_err(|_| {
            UpstreamError::DnsError(format!(
              "DNS resolve for '{addr}' timed out"
            ))
          })?
          .map_err(classify_connect_error)?;
      let stream =
        super::tcp_connect::connect(resolved, connect_timeout)
          .await
          .map_err(|e| classify_tcp_connect_error(&addr, e))?;

      let upstream_addr = stream.peer_addr().ok();

      let server_name =
        rustls::pki_types::ServerName::try_from(hostname.clone())
          .map_err(|e| {
            UpstreamError::DnsError(format!("invalid server name: {e}"))
          })?;
      let connector = tokio_rustls::TlsConnector::from(tls);
      let tls_stream = tokio::time::timeout(
        tls_handshake_timeout,
        connector.connect(server_name, stream),
      )
      .await
      .map_err(|_| {
        UpstreamError::ConnectionTimeout(format!(
          "TLS handshake with {addr} timed out"
        ))
      })?
      .map_err(|e| classify_tls_handshake_error(e.into()))?;

      let io = TokioIo::new(tls_stream);
      negotiate_tunnel(
        io,
        target,
        &user,
        &tracker,
        upstream_addr,
        tunnel_idle_timeout,
      )
      .await
    })
  }

  fn close(&self) {
    self.client.close();
  }
}

async fn negotiate_tunnel<I>(
  io: I,
  target: &ConnectTarget,
  user: &Option<crate::config::UserCredential>,
  tracker: &StreamTracker,
  upstream_addr: Option<std::net::SocketAddr>,
  tunnel_idle_timeout: Duration,
) -> Result<ConnectResult, UpstreamError>
where
  I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
  let (mut sr, conn) = http1::handshake(io).await.map_err(|e| {
    UpstreamError::ProxyInternalError(format!(
      "HTTP/1.1 handshake failed: {e}"
    ))
  })?;

  let req = build_connect_request(target, user);
  let resp_fut = sr.send_request(req);

  // Drive the connection via tracker (spawn_local + graceful
  // shutdown support) while waiting for the CONNECT response.
  tracker.register_connection(async move {
    if let Err(e) = conn.with_upgrades().await {
      warn!(
        "http_upstream: CONNECT connection ended before upgrade: {e}"
      );
    }
  });

  let mut resp = resp_fut
    .await
    .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

  let upstream_proxy_status =
    crate::proxy_status::take_proxy_status(resp.headers_mut());

  // RFC 9110 §9.3.6: every 2xx establishes a CONNECT tunnel.
  if !resp.status().is_success() {
    return Err(UpstreamError::UpstreamConnectError {
      status: resp.status(),
      upstream_proxy_status,
    });
  }

  // Hyper 1.6.0 incorrectly classifies 204 before checking CONNECT,
  // so it does not expose upgraded I/O for that status. Keep its real
  // failure visible; the dependency case is recorded in
  // tests/integration/test_connect_upstream_status.py.
  let upgrade = hyper::upgrade::on(&mut resp);
  let upgraded = upgrade
    .await
    .map_err(|e| UpstreamError::ConnectionTerminated(e.to_string()))?;

  Ok(ConnectResult {
    transport: Box::new(TokioIo::new(upgraded)),
    upstream_addr,
    upstream_proxy_status,
    tunnel_idle_timeout,
  })
}
