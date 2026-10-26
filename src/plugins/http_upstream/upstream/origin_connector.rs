//! module: origin_connector
//! responsibility: establish HTTP or HTTPS origin transports
//! public operations: OriginConnector::new, Service<Uri>,
//! OriginConnection data entities: OriginConnector, OriginConnection,
//! Transport tests: origin_connector_tests.rs; test_https_forward.py

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::{
  Connected, Connection, HttpConnector,
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tower::{Service, ServiceExt};

use super::address_resolution::TimeoutResolver;
use crate::io_stream::Io;
use crate::plugins::http_upstream::config::Upstream;

#[derive(Clone)]
pub(super) struct OriginConnector {
  http: HttpConnector<TimeoutResolver>,
  https: HttpConnector<TimeoutResolver>,
  tls: tokio_rustls::TlsConnector,
  tls_handshake_timeout: Duration,
  endpoint: Option<Uri>,
  expected_alpn: Option<&'static [u8]>,
  prepared:
    std::sync::Arc<std::sync::Mutex<Option<TokioIo<OriginConnection>>>>,
}

impl OriginConnector {
  pub(super) fn new(
    config: &Upstream,
    tls: Arc<rustls::ClientConfig>,
  ) -> Self {
    let mut http = HttpConnector::new_with_resolver(
      TimeoutResolver::new(config.dns_resolve_timeout),
    );
    http.set_connect_timeout(Some(config.connect_timeout));
    let mut https = http.clone();
    https.enforce_http(false);
    https.set_connect_timeout(Some(config.https_connect_timeout));
    Self {
      http,
      https,
      tls: tokio_rustls::TlsConnector::from(tls),
      tls_handshake_timeout: config.tls_handshake_timeout,
      endpoint: None,
      expected_alpn: None,
      prepared: Arc::new(std::sync::Mutex::new(None)),
    }
  }

  pub(super) fn routed(
    mut self,
    endpoint: Uri,
    expected_alpn: Option<&'static [u8]>,
  ) -> Self {
    self.endpoint = Some(endpoint);
    self.expected_alpn = expected_alpn;
    self
  }

  pub(super) async fn prepare(&mut self, uri: Uri) -> io::Result<()> {
    let connection = self.clone().oneshot(uri).await?;
    *self.prepared.lock().expect("prepared transport lock poisoned") =
      Some(connection);
    Ok(())
  }
}

impl Service<Uri> for OriginConnector {
  type Error = io::Error;
  type Future = Pin<
    Box<
      dyn Future<Output = Result<Self::Response, Self::Error>> + Send,
    >,
  >;
  type Response = TokioIo<OriginConnection>;

  fn poll_ready(
    &mut self,
    _cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, uri: Uri) -> Self::Future {
    if let Some(connection) = self
      .prepared
      .lock()
      .expect("prepared transport lock poisoned")
      .take()
    {
      return Box::pin(async { Ok(connection) });
    }
    let https = uri.scheme() == Some(&http::uri::Scheme::HTTPS);
    let connector =
      if https { self.https.clone() } else { self.http.clone() };
    let tls = self.tls.clone();
    let timeout = self.tls_handshake_timeout;
    let endpoint = self.endpoint.clone();
    let expected_alpn = self.expected_alpn;
    Box::pin(async move {
      let host = uri
        .host()
        .ok_or_else(|| {
          io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing origin host",
          )
        })?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
      let stream = connector
        .oneshot(endpoint.unwrap_or(uri))
        .await
        .map_err(|error| {
          let mut source: Option<&(dyn StdError + 'static)> =
            Some(&error);
          let mut kind = io::ErrorKind::Other;
          while let Some(current) = source {
            if let Some(error) = current.downcast_ref::<io::Error>() {
              kind = error.kind();
              break;
            }
            source = current.source();
          }
          io::Error::new(kind, error)
        })?
        .into_inner();
      let transport = if https {
        let name = rustls::pki_types::ServerName::try_from(host)
          .map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, error)
          })?;
        let stream =
          tokio::time::timeout(timeout, tls.connect(name, stream))
            .await
            .map_err(|_| {
              io::Error::new(
                io::ErrorKind::TimedOut,
                "origin TLS handshake timed out",
              )
            })??;
        if expected_alpn.is_some_and(|expected| {
          stream.get_ref().1.alpn_protocol() != Some(expected)
        }) {
          return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "origin did not negotiate advertised ALPN",
          ));
        }
        Transport::Tls(Box::new(stream))
      } else {
        Transport::Tcp(stream)
      };
      Ok(TokioIo::new(OriginConnection { transport }))
    })
  }
}

enum Transport {
  Tcp(TcpStream),
  Tls(Box<TlsStream<TcpStream>>),
}

pub(super) struct OriginConnection {
  transport: Transport,
}

impl OriginConnection {
  fn io(&mut self) -> &mut dyn Io {
    match &mut self.transport {
      Transport::Tcp(stream) => stream,
      Transport::Tls(stream) => stream.as_mut(),
    }
  }
}

impl Connection for OriginConnection {
  fn connected(&self) -> Connected {
    match &self.transport {
      Transport::Tcp(stream) => stream.connected(),
      Transport::Tls(stream) => {
        let connected = stream.get_ref().0.connected();
        if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
          connected.negotiated_h2()
        } else {
          connected
        }
      }
    }
  }
}

impl AsyncRead for OriginConnection {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(self.io()).poll_read(cx, buf)
  }
}

impl AsyncWrite for OriginConnection {
  fn is_write_vectored(&self) -> bool {
    match &self.transport {
      Transport::Tcp(stream) => stream.is_write_vectored(),
      Transport::Tls(stream) => stream.is_write_vectored(),
    }
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[io::IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    Pin::new(self.io()).poll_write_vectored(cx, bufs)
  }

  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(self.io()).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(self.io()).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(self.io()).poll_shutdown(cx)
  }
}
