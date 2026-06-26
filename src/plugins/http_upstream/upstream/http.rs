use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use http::Uri;
use hyper::client::conn::http1;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::Connected;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Service;
use tracing::warn;

use super::address_resolution::resolve_addresses;
use super::connect_request::build_connect_request;
use super::proxy_auth::apply_proxy_auth;
use super::{ClientProtocol, ConnectResult};
use crate::context::{RequestContext, get_server_id};
use crate::http_message::{
  BytesBufBodyWrapper, RequestBody, Response, ResponseBody,
  append_proxy_status, build_error_response,
  build_proxy_status_with_status,
};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_connect_error, classify_http_client_error,
  classify_tls_handshake_error,
};
use crate::plugins::http_upstream::target_parser::{
  self, ForwardTarget,
};
use crate::tracker::StreamTracker;

// ============================================================================
// Proxied Connection Wrapper
// ============================================================================

/// Wrapper that marks a connection as proxied
/// (`Connected::proxy(true)`), so hyper sends absolute-form URIs and
/// pools by connected address.
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

impl<T: hyper_util::client::legacy::connect::Connection>
  hyper_util::client::legacy::connect::Connection for Proxied<T>
{
  fn connected(&self) -> Connected {
    self.0.connected().proxy(true)
  }
}

/// Newtype wrapper for TlsStream so we can implement Connection for it.
/// Proxied<TokioIo<TlsConn>> will then have both Read/Write and
/// Connection.
pub(crate) struct TlsConn(
  pub(crate) tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
);

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

async fn connect_to_resolved_addresses(
  addresses: Vec<SocketAddr>,
  connect_timeout: Duration,
) -> std::io::Result<tokio::net::TcpStream> {
  let deadline = tokio::time::Instant::now() + connect_timeout;
  let mut last_error: Option<std::io::Error> = None;

  for addr in addresses {
    let now = tokio::time::Instant::now();
    if now >= deadline {
      return Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "connect timed out",
      ));
    }

    match tokio::time::timeout(
      deadline - now,
      tokio::net::TcpStream::connect(addr),
    )
    .await
    {
      Ok(Ok(stream)) => return Ok(stream),
      Ok(Err(e)) => {
        last_error = Some(e);
      }
      Err(_) => {
        return Err(std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "connect timed out",
        ));
      }
    }
  }

  Err(last_error.unwrap_or_else(|| {
    std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "no resolved addresses",
    )
  }))
}

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
/// Returns `Proxied` so hyper sends absolute-form URI and pools by
/// proxy address.
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
  type Response = Proxied<TokioIo<tokio::net::TcpStream>>;

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
        connect_to_resolved_addresses(addresses, timeout).await?;
      Ok(Proxied(TokioIo::new(stream)))
    })
  }
}

/// Connects to a pre-configured upstream proxy address via TLS.
/// Same as `ProxyConnector` but wraps the TCP stream with a TLS
/// handshake. Always operates in proxy mode (TLS to proxy, not to
/// origin).
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
  type Response = Proxied<TokioIo<TlsConn>>;

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
      let Proxied(tcp_io) = inner.call(uri).await?;
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
      Ok(Proxied(TokioIo::new(TlsConn(tls_stream))))
    })
  }
}

// ============================================================================
// HTTP/HTTPS Forward
// ============================================================================

/// Forward an HTTP request over HTTP/1.1 or HTTPS/1.1 to the upstream
/// proxy. Uses hyper::Client which handles connection pooling
/// internally.
pub(super) async fn chain_forward_http<C>(
  client: Client<C, RequestBody>,
  user: Option<crate::config::UserCredential>,
  target: &ForwardTarget,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Response
where
  C: hyper_util::client::legacy::connect::Connect
    + Clone
    + Send
    + Sync
    + Unpin
    + 'static,
{
  let mut headers = req_headers.headers.clone();
  target_parser::strip_hop_by_hop_headers(&mut headers);
  let host_header = match target.host_header_value() {
    Ok(value) => value,
    Err(e) => {
      warn!("http_upstream: invalid forward target authority: {e}");
      return build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      );
    }
  };
  headers.insert(http::header::HOST, host_header);

  let mut temp_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(target.absolute_uri().clone())
    .body(())
    .unwrap();
  apply_proxy_auth(&user, &mut temp_req);
  for (name, value) in temp_req.headers().iter() {
    headers.insert(name.clone(), value.clone());
  }

  let mut fwd_req_builder = http::Request::builder()
    .method(req_headers.method)
    .uri(target.absolute_uri().clone());
  for (name, value) in headers.iter() {
    fwd_req_builder = fwd_req_builder.header(name, value);
  }

  let fwd_req = fwd_req_builder.body(req_body).unwrap();

  let forward_start = Instant::now();
  let upstream_resp = match client.request(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("http_upstream: forward request failed: {e}");
      return classify_http_client_error(e.into()).to_response(ctx);
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    upstream_resp.status().as_str().to_string(),
  );

  let (resp_parts, resp_body) = upstream_resp.into_parts();
  let mut resp_headers = resp_parts.headers;
  target_parser::strip_hop_by_hop_headers(&mut resp_headers);

  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers
    .remove(http::header::HeaderName::from_static("proxy-status"));

  let mut resp = http::Response::builder().status(resp_parts.status);
  for (name, value) in resp_headers.iter() {
    resp = resp.header(name, value);
  }

  if let Some(ref id) = get_server_id(ctx) {
    let our_entry =
      build_proxy_status_with_status(id, resp_parts.status.as_u16());
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_ps.as_ref(), &our_entry),
    );
  } else if let Some(ps) = upstream_ps {
    resp = resp.header(
      http::header::HeaderName::from_static("proxy-status"),
      ps,
    );
  }

  let wrapped_body = BytesBufBodyWrapper::new(resp_body);
  let boxed_resp_body = ResponseBody::new(wrapped_body);

  match resp.body(boxed_resp_body) {
    Ok(r) => r,
    Err(e) => {
      warn!("http_upstream: failed to build response: {e}");
      build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      )
    }
  }
}

// ============================================================================
// HTTP Client (cleartext proxy or direct-to-origin)
// ============================================================================

pub(crate) struct HttpClient<C> {
  pub(crate) client: Client<C, RequestBody>,
  pub(crate) proxy_addr: Option<String>, /* None = direct-to-origin,
                                          * Some = proxy mode */
  pub(crate) connect_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl<C> ClientProtocol for HttpClient<C>
where
  C: hyper_util::client::legacy::connect::Connect
    + Clone
    + Send
    + Sync
    + Unpin
    + 'static,
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
    target: &'a str,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let target = target.to_string();
    let proxy_addr = self.proxy_addr.clone();
    let connect_timeout = self.connect_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    let user = self.user.clone();
    Box::pin(async move {
      match proxy_addr {
        None => {
          let dns_timeout = self.dns_resolve_timeout;
          let resolved = tokio::time::timeout(
            dns_timeout,
            resolve_addresses(&target),
          )
          .await
          .map_err(|_| {
            UpstreamError::DnsError(format!(
              "DNS resolve for '{target}' timed out"
            ))
          })?
          .map_err(classify_connect_error)?;

          // Direct mode: raw TCP connect to target
          let stream =
            connect_to_resolved_addresses(resolved, connect_timeout)
              .await
              .map_err(|e| classify_tcp_connect_error(&target, e))?;

          let upstream_addr = stream.peer_addr().ok();

          Ok(ConnectResult {
            transport: Box::new(stream),
            upstream_addr,
            upstream_proxy_status: None,
            tunnel_idle_timeout,
          })
        }
        Some(ref addr) => {
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
            connect_to_resolved_addresses(resolved, connect_timeout)
              .await
              .map_err(|e| classify_tcp_connect_error(addr, e))?;

          let upstream_addr = stream.peer_addr().ok();
          let io = TokioIo::new(stream);
          let (mut sr, conn) =
            http1::handshake(io).await.map_err(|e| {
              UpstreamError::ProxyInternalError(format!(
                "HTTP/1.1 handshake failed: {e}"
              ))
            })?;

          let req = build_connect_request(&target, &user);
          let resp_fut = sr.send_request(req);
          tracker.register_connection(async move {
            if let Err(e) = conn.with_upgrades().await {
              warn!(
                "http_upstream: HTTP CONNECT connection ended before \
                 upgrade: {e}"
              );
            }
          });

          let mut resp = resp_fut.await.map_err(|e| {
            UpstreamError::ConnectionTerminated(e.to_string())
          })?;

          let upstream_proxy_status = resp
            .headers()
            .get(::http::header::HeaderName::from_static(
              "proxy-status",
            ))
            .cloned();

          if resp.status() != ::http::StatusCode::OK {
            return Err(UpstreamError::UpstreamConnectError {
              status: resp.status(),
              upstream_proxy_status,
            });
          }

          let upgrade = hyper::upgrade::on(&mut resp);
          let upgraded = upgrade.await.map_err(|e| {
            UpstreamError::ConnectionTerminated(e.to_string())
          })?;

          Ok(ConnectResult {
            transport: Box::new(TokioIo::new(upgraded)),
            upstream_addr,
            upstream_proxy_status,
            tunnel_idle_timeout,
          })
        }
      }
    })
  }
}

// ============================================================================
// HTTPS Client (TLS to proxy, always proxy mode)
// ============================================================================

pub(crate) struct HttpsClient {
  pub(crate) client: Client<TlsProxyConnector, RequestBody>,
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
    target: &'a str,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let target = target.to_string();
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
        connect_to_resolved_addresses(resolved, connect_timeout)
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
      let (mut sr, conn) = http1::handshake(io).await.map_err(|e| {
        UpstreamError::ProxyInternalError(format!(
          "HTTPS/1.1 handshake failed: {e}"
        ))
      })?;

      let req = build_connect_request(&target, &user);
      let resp_fut = sr.send_request(req);

      // Drive the connection via tracker (spawn_local + graceful
      // shutdown support) while waiting for the CONNECT response.
      tracker.register_connection(async move {
        if let Err(e) = conn.with_upgrades().await {
          warn!(
            "http_upstream: HTTPS CONNECT connection ended before \
             upgrade: {e}"
          );
        }
      });

      let mut resp = resp_fut.await.map_err(|e| {
        UpstreamError::ConnectionTerminated(e.to_string())
      })?;

      let upstream_proxy_status = resp
        .headers()
        .get(::http::header::HeaderName::from_static("proxy-status"))
        .cloned();

      if resp.status() != ::http::StatusCode::OK {
        return Err(UpstreamError::UpstreamConnectError {
          status: resp.status(),
          upstream_proxy_status,
        });
      }

      let upgrade = hyper::upgrade::on(&mut resp);
      let upgraded = upgrade.await.map_err(|e| {
        UpstreamError::ConnectionTerminated(e.to_string())
      })?;

      Ok(ConnectResult {
        transport: Box::new(TokioIo::new(upgraded)),
        upstream_addr,
        upstream_proxy_status,
        tunnel_idle_timeout,
      })
    })
  }
}
