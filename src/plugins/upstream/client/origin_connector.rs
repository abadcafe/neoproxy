//! module: origin_connector
//! responsibility: establish HTTP or HTTPS origin transports
//! public operations: OriginConnector::new, Service<Uri>,
//! OriginConnection data entities: OriginConnector, OriginConnection,
//! Transport tests: origin_connector_tests.rs; test_https_forward.py

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tower::Service;

use super::observation::ConnectionObservation;
use super::tcp_options::TcpOptions;
use crate::io_stream::Io;
use crate::plugins::upstream::config::Upstream;

#[derive(Clone)]
pub(super) struct OriginConnector {
  connect_timeout: Duration,
  endpoint: std::net::SocketAddr,
  tcp_options: TcpOptions,
  tls: tokio_rustls::TlsConnector,
  tls_handshake_timeout: Duration,
}

impl OriginConnector {
  pub(super) fn new(
    config: &Upstream,
    tls: Arc<rustls::ClientConfig>,
    endpoint: std::net::SocketAddr,
  ) -> anyhow::Result<Self> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Self {
      connect_timeout: config.connect_timeout,
      endpoint,
      tcp_options: TcpOptions {
        time: config.tcp_keep_alive_time,
        interval: config.tcp_keep_alive_interval,
        retries: config.tcp_keep_alive_retries,
      },
      tls: tokio_rustls::TlsConnector::from(Arc::new(tls)),
      tls_handshake_timeout: config.tls_handshake_timeout,
    })
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
    let connector = self.clone();
    Box::pin(async move {
      let observation = ConnectionObservation::new();
      let result = async {
        let https = match uri.scheme_str() {
          Some("https") => true,
          Some("http") => false,
          _ => {
            return Err(io::Error::new(
              io::ErrorKind::InvalidInput,
              "invalid origin scheme",
            ));
          }
        };
        let host = uri
          .host()
          .ok_or_else(|| {
            io::Error::new(
              io::ErrorKind::InvalidInput,
              "missing origin host",
            )
          })?
          .trim_start_matches('[')
          .trim_end_matches(']');
        let host = host.to_owned();
        let address = connector.endpoint;
        let started = std::time::Instant::now();
        let stream = super::tcp_connect::connect(
          vec![address],
          connector.connect_timeout,
        )
        .await?;
        connector.tcp_options.apply(&stream)?;
        let peer = stream.peer_addr().ok();
        let local = stream.local_addr().ok();
        let tcp_elapsed = started.elapsed();
        observation.tcp(peer, local, tcp_elapsed);
        let transport = if https {
          let name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|error| {
              io::Error::new(io::ErrorKind::InvalidInput, error)
            })?;
          let tls_started = std::time::Instant::now();
          let result = tokio::time::timeout(
            connector.tls_handshake_timeout,
            connector.tls.connect(name, stream),
          )
          .await
          .map_err(|_| {
            io::Error::new(
              io::ErrorKind::TimedOut,
              "origin TLS handshake timed out",
            )
          })
          .and_then(std::convert::identity);
          observation.tls(tls_started.elapsed());
          Transport::Tls(Box::new(result?))
        } else {
          Transport::Tcp(stream)
        };
        Ok(TokioIo::new(OriginConnection {
          transport,
          observation: observation.clone(),
        }))
      }
      .await;
      result.map_err(|error| observation.error(error))
    })
  }
}

enum Transport {
  Tcp(TcpStream),
  Tls(Box<TlsStream<TcpStream>>),
}

pub(super) struct OriginConnection {
  transport: Transport,
  observation: ConnectionObservation,
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
    let connected = match &self.transport {
      Transport::Tcp(stream) => stream.connected(),
      Transport::Tls(stream) => stream.get_ref().0.connected(),
    };
    connected.extra(self.observation.clone())
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
