use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Uri;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::Connected;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tower::Service;
use tracing::warn;

use super::utils::{
  apply_proxy_auth, build_connect_request, resolve_address,
};
use super::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_utils::{
  BytesBufBodyWrapper, RequestBody, Response, ResponseBody,
  append_proxy_status, build_error_response,
  build_proxy_status_with_status,
};
use crate::listeners::utils::get_server_id;
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_connect_error, classify_tls_handshake_error,
};
use crate::plugins::utils;
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
}

impl ProxyConnector {
  pub(crate) fn new(
    proxy_addr: String,
    connect_timeout: Duration,
  ) -> Self {
    Self { proxy_addr, connect_timeout }
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
    Box::pin(async move {
      let addr = resolve_address(&proxy_addr).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e)
      })?;
      let stream = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(addr),
      )
      .await
      .map_err(|_| {
        std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "connect timed out",
        )
      })??;
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
// Rewind Wrapper
// ============================================================================

pub(super) struct Rewind<T> {
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
// HTTP/HTTPS Forward
// ============================================================================

/// Forward an HTTP request over HTTP/1.1 or HTTPS/1.1 to the upstream
/// proxy. Uses hyper::Client which handles connection pooling
/// internally.
pub(super) async fn chain_forward_http<C>(
  client: Client<C, RequestBody>,
  user: Option<crate::config::UserCredential>,
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
  let body_bytes = match req_body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(e) => {
      warn!("http_upstream: failed to collect request body: {e}");
      return build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Failed to read request body",
      );
    }
  };

  let mut headers = req_headers.headers.clone();
  utils::strip_hop_by_hop_headers(&mut headers);

  let mut temp_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(req_headers.uri.clone())
    .body(())
    .unwrap();
  apply_proxy_auth(&user, &mut temp_req);
  for (name, value) in temp_req.headers().iter() {
    headers.insert(name.clone(), value.clone());
  }

  let mut fwd_req_builder = http::Request::builder()
    .method(req_headers.method)
    .uri(req_headers.uri);
  for (name, value) in headers.iter() {
    fwd_req_builder = fwd_req_builder.header(name, value);
  }

  let body = http_body_util::Full::new(body_bytes);
  let boxed_body = RequestBody::new(BytesBufBodyWrapper::new(body));
  let fwd_req = fwd_req_builder.body(boxed_body).unwrap();

  let forward_start = Instant::now();
  let upstream_resp = match client.request(fwd_req).await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("http_upstream: forward request failed: {e}");
      return UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx);
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
  utils::strip_hop_by_hop_headers(&mut resp_headers);

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
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let client = self.client.clone();
    let user = self.user.clone();
    Box::pin(async move {
      Ok(
        chain_forward_http(client, user, req_headers, req_body, ctx)
          .await,
      )
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a str,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
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
          // Direct mode: raw TCP connect to target
          let stream = tokio::time::timeout(
            connect_timeout,
            tokio::net::TcpStream::connect(&target),
          )
          .await
          .map_err(|_| {
            UpstreamError::ConnectionTimeout(format!(
              "direct connect to {target} timed out"
            ))
          })?
          .map_err(|e| classify_connect_error(e.into()))?;

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
          let resolved = resolve_address(addr)
            .map_err(|e| classify_connect_error(e))?;
          let stream = tokio::time::timeout(
            connect_timeout,
            tokio::net::TcpStream::connect(resolved),
          )
          .await
          .map_err(|_| {
            UpstreamError::ConnectionTimeout(format!(
              "TCP connect to {addr} timed out"
            ))
          })?
          .map_err(|e| classify_connect_error(e.into()))?;

          let upstream_addr = stream.peer_addr().ok();
          let io = TokioIo::new(stream);
          let (mut sr, conn) =
            http1::handshake(io).await.map_err(|e| {
              UpstreamError::ProxyInternalError(format!(
                "HTTP/1.1 handshake failed: {e}"
              ))
            })?;

          let req = build_connect_request(&target, &user);
          let resp = sr.send_request(req).await.map_err(|e| {
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

          let parts = conn.without_shutdown().await.map_err(|e| {
            UpstreamError::ConnectionTerminated(e.to_string())
          })?;

          Ok(ConnectResult {
            transport: Box::new(Rewind::new(
              parts.io.into_inner(),
              Some(parts.read_buf),
            )),
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
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl ClientProtocol for HttpsClient {
  fn forward<'a>(
    &'a self,
    _tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let client = self.client.clone();
    let user = self.user.clone();
    Box::pin(async move {
      Ok(
        chain_forward_http(client, user, req_headers, req_body, ctx)
          .await,
      )
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a str,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    _tracker: &'a Rc<StreamTracker>,
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
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTPS upstream".into(),
        )
      })?;

      let resolved = resolve_address(&addr)
        .map_err(|e| classify_connect_error(e))?;
      let stream = tokio::time::timeout(
        connect_timeout,
        tokio::net::TcpStream::connect(resolved),
      )
      .await
      .map_err(|_| {
        UpstreamError::ConnectionTimeout(format!(
          "TCP connect to {addr} timed out"
        ))
      })?
      .map_err(|e| classify_connect_error(e.into()))?;

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
      let resp = sr.send_request(req).await.map_err(|e| {
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

      let parts = conn.without_shutdown().await.map_err(|e| {
        UpstreamError::ConnectionTerminated(e.to_string())
      })?;

      Ok(ConnectResult {
        transport: Box::new(Rewind::new(
          parts.io.into_inner(),
          Some(parts.read_buf),
        )),
        upstream_addr,
        upstream_proxy_status,
        tunnel_idle_timeout,
      })
    })
  }
}
