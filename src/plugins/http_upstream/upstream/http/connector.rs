//! module: connector
//! responsibility: establish typed TCP/TLS transports to a configured
//! proxy public operations: ProxyConnector::new,
//! TlsProxyConnector::new, tower::Service data entities:
//! ProxyConnector, TlsProxyConnector tests: connector_tests.rs;
//! HTTP/HTTPS proxy process contracts

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use tower::Service;

use super::super::address_resolution::{
  dns_io_error, resolve_addresses,
};

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
        dns_io_error(std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          format!("DNS resolve for '{proxy_addr}' timed out"),
        ))
      })?
      .map_err(std::io::Error::other)?;
      let stream =
        super::super::tcp_connect::connect(addresses, timeout).await?;
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

impl super::ProxyIo for TokioIo<tokio::net::TcpStream> {
  fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
    self.inner().peer_addr()
  }
}
impl super::ProxyIo
  for TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>
{
  fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
    self.inner().get_ref().0.peer_addr()
  }
}
