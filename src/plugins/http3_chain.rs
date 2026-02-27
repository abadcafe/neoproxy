use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fs, future, path};

use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};
use h3::client as h3_cli;
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use rustls::pki_types::CertificateDer;
use rustls_native_certs::CertificateResult;
use serde::Deserialize;
use tokio::{io, task};
use tracing::{error, info, warn};

use super::utils;
use crate::plugin;

static ALPN: &[u8] = b"h3";

struct Proxy {
  address: SocketAddr,
  conn_handle: Option<task::JoinHandle<Result<()>>>,
  requester: Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
  weight: usize,
  current_weight: usize,
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
  proxies: Vec<Proxy>,
}

impl ProxyGroup {
  fn new(
    ca_path: path::PathBuf,
    addresses: Vec<(SocketAddr, usize)>,
  ) -> Self {
    let mut proxies = vec![];
    for (addr, weight) in addresses {
      proxies.push(Proxy {
        address: addr,
        conn_handle: None,
        requester: None,
        weight: weight,
        current_weight: 0,
      });
    }

    Self { ca_path, proxies }
  }

  fn schedule_wrr(&mut self) -> usize {
    let total = self.proxies.iter().fold(0, |t, p| t + p.weight);
    let mut selected_idx = 0usize;
    let mut selected_weight = 0usize;
    for (i, p) in self.proxies.iter_mut().enumerate() {
      p.current_weight += p.weight;
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

    // load certificate of CA who issues the server certificate
    if let Err(e) =
      roots.add(CertificateDer::from(fs::read(self.ca_path.as_path())?))
    {
      error!("failed to parse trust anchor: {e}");
    }

    let mut tls_config = rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth();

    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];

    // Write all Keys to a file if SSLKEYLOGFILE env is set.
    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut cli_endpoint =
      quinn::Endpoint::client("[::]:0".parse().unwrap())?;

    let cli_config = quinn::ClientConfig::new(Arc::new(
      quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    cli_endpoint.set_default_client_config(cli_config);

    let addr = self.proxies[proxy_idx].address;
    let host = addr.to_string();
    let conn = cli_endpoint.connect(addr, host.as_str())?.await?;

    info!("QUIC connection established");
    Ok(conn)
  }

  async fn get_proxy_conn(
    &mut self,
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
          Ok(res) => match res {
            Err(e) => {
              info!("connection of {} finished: {e}", proxy.address);
            }
            Ok(_) => {}
          },
        }
      } else {
        return Ok(proxy.requester.as_ref().unwrap().clone());
      }
    }

    let conn = self.new_proxy_conn(idx).await?;
    let (conn, requester) =
      h3::client::new(h3_quinn::Connection::new(conn)).await?;
    let handle = task::spawn_local(connection_maintaining(conn));

    let proxy = &mut self.proxies[idx];
    let _ = proxy.conn_handle.insert(handle);
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

async fn request_body_transfering(
  mut req_body: plugin::RequestBody,
  mut proxy_sending_stream: h3_cli::RequestStream<
    h3_quinn::SendStream<Bytes>,
    Bytes,
  >,
  shutdown: plugin::ShutdownHandle,
) -> Result<()> {
  let res = loop {
    let data = match req_body.frame().await {
      // stream finished.
      None => break Ok(()),
      Some(res) => match res {
        Err(e) => break Err(e),
        Ok(frame) => match frame.into_data() {
          Err(_) => break Err(anyhow!("unexpected non-data frame")),
          Ok(data) => data,
        },
      },
    };

    let res = proxy_sending_stream.send_data(data).await;
    if let Err(e) = res {
      break Err(e.into());
    }
  };

  if let Err(e) = proxy_sending_stream.finish().await {
    warn!("sending stream finishing error: {e}");
  }

  res
}

struct H3ReceivingStreamBody {
  inner: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl H3ReceivingStreamBody {
  fn new(
    inner: h3_cli::RequestStream<h3_quinn::RecvStream, Bytes>,
  ) -> Self {
    Self { inner }
  }
}

impl Body for H3ReceivingStreamBody {
  type Data = Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>>>> {
    let poll = self.inner.poll_recv_data(cx);
    match poll {
      Poll::Pending => Poll::Pending,
      Poll::Ready(res) => match res {
        Err(err) => Poll::Ready(Some(Err(err.into()))),
        Ok(opt) => match opt {
          None => Poll::Ready(None),
          Some(mut data) => {
            // todo: avoid this coping overhead.
            let data = data.copy_to_bytes(data.remaining());
            Poll::Ready(Some(Ok(Frame::data(data))))
          }
        },
      },
    }
  }
}

struct H3SendingStreamWriter(
  h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
);

impl H3SendingStreamWriter {
  fn new(
    inner: h3_cli::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  ) -> Self {
    Self(inner)
  }
}

impl io::AsyncWrite for H3SendingStreamWriter {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    let buf = Bytes::copy_from_slice(buf);
    let buf_size = buf.remaining();
    let fut = self.0.send_data(buf);
    Box::pin(fut).as_mut().poll(cx).map(|r| {
      if let Err(e) = r {
        if e.is_h3_no_error() {
          Ok(buf_size)
        } else {
          Err(std::io::Error::other(e))
        }
      } else {
        Ok(buf_size)
      }
    })
  }

  fn poll_flush(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), std::io::Error>> {
    let fut = self.0.finish();
    Box::pin(fut)
      .as_mut()
      .poll(cx)
      .map_err(|e| std::io::Error::other(e))
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
}

#[derive(Clone)]
struct Http3ChainService {
  proxy_group: Rc<RefCell<ProxyGroup>>,
  transfering_set: Rc<utils::TransferingSet>,
  shutdown_handle: plugin::ShutdownHandle,
}

impl Http3ChainService {
  fn new(sargs: plugin::SerializedArgs) -> Result<plugin::Service> {
    let args: Http3ChainServiceArgs = serde_yaml::from_value(sargs)?;
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
      );

    Ok(plugin::Service::new(Self {
      proxy_group: Rc::new(RefCell::new(proxy_group)),
      transfering_set: Rc::new(utils::TransferingSet::new()),
      shutdown_handle: plugin::ShutdownHandle::new(),
    }))
  }
}

impl tower::Service<plugin::Request> for Http3ChainService {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<plugin::Response>>>>;
  type Response = plugin::Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    cx.waker().clone().wake();
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, req: plugin::Request) -> Self::Future {
    let pg = self.proxy_group.clone();
    let ts = self.transfering_set.clone();
    let (req_headers, req_body) = req.into_parts();
    let shutdown = self.shutdown_handle.clone();
    Box::pin(async move {
      let (host, port) = utils::is_connect_method(&req_headers)?;
      let mut requester = pg.borrow_mut().get_proxy_conn().await?;
      let proxy_req =
        http::Request::connect(format!("{host}:{port}")).body(())?;
      let mut proxy_stream = requester.send_request(proxy_req).await?;
      let proxy_resp = proxy_stream.recv_response().await?;
      if !proxy_resp.status().is_success() {
        return Ok(build_empty_response(proxy_resp.status()));
      }

      // interface proxy receiving stream with response body.
      let (sending_stream, receiving_stream) = proxy_stream.split();
      let resp_body = plugin::ResponseBody::new(
        H3ReceivingStreamBody::new(receiving_stream),
      );
      let mut resp = plugin::Response::new(resp_body);
      *resp.status_mut() = http::StatusCode::OK;

      // transfer request body's data frames to proxy sending stream.
      ts.new_transfering(
        tokio_util::io::StreamReader::new(
          req_body
            .map_err(|e| std::io::Error::other(e))
            .into_data_stream(),
        ),
        H3SendingStreamWriter::new(sending_stream),
      )?;

      Ok(resp)
    })
  }
}

struct Http3ChainPlugin {
  service_builders:
    HashMap<&'static str, Box<dyn plugin::BuildService>>,
}

impl Http3ChainPlugin {
  fn new() -> Self {
    let builder: Box<dyn plugin::BuildService> =
      Box::new(move |a| Http3ChainService::new(a));
    let service_builders = HashMap::from([("http3_chain", builder)]);
    Self { service_builders }
  }
}

impl plugin::Plugin for Http3ChainPlugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn plugin::BuildService>> {
    self.service_builders.get(name)
  }
}

pub fn create_plugin() -> Box<dyn plugin::Plugin> {
  Box::new(Http3ChainPlugin::new())
}
