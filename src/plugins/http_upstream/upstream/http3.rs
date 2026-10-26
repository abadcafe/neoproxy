mod quic_connect;
#[cfg(test)]
mod quic_connect_tests;
mod upload;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client as h3_cli;
use http_body::{Body, Frame, SizeHint};
use tracing::{info, warn};
use upload::Upload;

use super::protocol::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_message::{
  RequestBody, Response, ResponseBody, build_error_response,
};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_quic_error,
};
use crate::plugins::http_upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

// ============================================================================
// HTTP/3 Address State
// ============================================================================

/// Per-address, worker-local H3 connection state shared through an
/// Rc<tokio::sync::Mutex<_>>. The lock protects connection setup and
/// sender cloning, not the lifetime of individual request streams.
pub(crate) struct Http3AddressState {
  quinn_conn: Option<quinn::Connection>,
  send_request:
    Option<h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

impl Http3AddressState {
  pub(crate) fn new() -> Self {
    Self { quinn_conn: None, send_request: None }
  }

  pub(crate) fn is_alive(&self) -> bool {
    self
      .quinn_conn
      .as_ref()
      .map(|c| c.close_reason().is_none())
      .unwrap_or(false)
      && self.send_request.is_some()
  }
}
use super::address_resolution::resolve_addresses;
use super::protocol::QuicConfig;
use super::proxy_auth::apply_proxy_auth;
use super::response::forward_response;

// ============================================================================
// Connection Establishment (H3)
// ============================================================================

pub(super) async fn establish_http3_connection(
  address: &str,
  hostname: Option<&str>,
  quic: &QuicConfig,
  tls_handshake_timeout: Duration,
  dns_timeout: Duration,
  tls_config: &rustls::ClientConfig,
  tracker: &Rc<StreamTracker>,
) -> Result<
  (
    quinn::Connection,
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
  ),
  UpstreamError,
> {
  let quinn_conn = create_quic_connection(
    address,
    hostname,
    quic,
    tls_config,
    tls_handshake_timeout,
    dns_timeout,
  )
  .await?;

  let (mut h3_conn, send_request) =
    h3::client::new(h3_quinn::Connection::new(quinn_conn.clone()))
      .await
      .map_err(|e| {
        UpstreamError::ProxyInternalError(format!(
          "H3 connection setup to {address} failed: {e}"
        ))
      })?;

  tracker.register_connection(async move {
    let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
  });

  info!("HTTP/3 connection established to {address}");
  Ok((quinn_conn, send_request))
}

async fn create_quic_connection(
  address: &str,
  hostname: Option<&str>,
  quic: &QuicConfig,
  tls_config: &rustls::ClientConfig,
  tls_handshake_timeout: Duration,
  dns_timeout: Duration,
) -> Result<quinn::Connection, UpstreamError> {
  let mut tls_config = tls_config.clone();
  tls_config.enable_early_data = true;
  tls_config.alpn_protocols = vec![b"h3".to_vec()];

  let mut cli_config = quinn::ClientConfig::new(Arc::new(
    quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
      .map_err(|e| {
        UpstreamError::TlsProtocolError(format!(
          "QUIC TLS config error: {e}"
        ))
      })?,
  ));

  let mut transport = quinn::TransportConfig::default();
  transport.keep_alive_interval(Some(quic.keep_alive_interval));
  if let Some(idle) = quic.max_idle_timeout {
    let ms = u64::try_from(idle.as_millis()).map_err(|_| {
      UpstreamError::ProxyInternalError(
        "quic max_idle_timeout too large".into(),
      )
    })?;
    transport.max_idle_timeout(Some(
      quinn::VarInt::from_u64(ms)
        .map_err(|_| {
          UpstreamError::ProxyInternalError(
            "quic max_idle_timeout overflow".into(),
          )
        })?
        .into(),
    ));
  }
  if let Some(v) = quic.max_concurrent_bidi_streams {
    transport.max_concurrent_bidi_streams(
      quinn::VarInt::from_u64(v).map_err(|_| {
        UpstreamError::ProxyInternalError(
          "max_concurrent_bidi_streams overflow".into(),
        )
      })?,
    );
  }
  if let Some(v) = quic.initial_mtu {
    transport.initial_mtu(v);
  }
  if let Some(v) = quic.send_window {
    transport.send_window(v);
  }
  if let Some(v) = quic.receive_window {
    transport.receive_window(quinn::VarInt::from_u64(v).map_err(
      |_| {
        UpstreamError::ProxyInternalError(
          "receive_window overflow".into(),
        )
      },
    )?);
  }
  cli_config.transport_config(Arc::new(transport));

  let addresses =
    tokio::time::timeout(dns_timeout, resolve_addresses(address))
      .await
      .map_err(|_| {
        UpstreamError::DnsError(format!(
          "DNS resolve for '{address}' timed out"
        ))
      })?
      .map_err(classify_quic_error)?;
  let host: &str = hostname.unwrap_or_else(|| {
    address.split_at(address.rfind(':').unwrap_or(address.len())).0
  });
  let host = host.trim_start_matches('[').trim_end_matches(']');
  let conn = quic_connect::connect(
    addresses,
    host,
    cli_config,
    tls_handshake_timeout,
  )
  .await?;

  info!("QUIC connection established to {address}");
  Ok(conn)
}

// ============================================================================
// H3 Forward
// ============================================================================

/// Forward an HTTP request over H3 to the upstream proxy.
pub(super) async fn chain_forward_http3(
  mut send_request: h3::client::SendRequest<
    h3_quinn::OpenStreams,
    Bytes,
  >,
  user: Option<crate::config::UserCredential>,
  target: &ForwardTarget,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
  tracker: &StreamTracker,
) -> Response {
  let mut fwd_req = http::Request::from_parts(req_headers, ());
  *fwd_req.uri_mut() = target.absolute_uri().clone();
  *fwd_req.version_mut() = http::Version::HTTP_3;
  crate::hop_headers::strip_connection_headers(fwd_req.headers_mut());
  let host_header = match target.host_header_value() {
    Ok(value) => value,
    Err(_) => {
      return build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      );
    }
  };
  fwd_req.headers_mut().insert(http::header::HOST, host_header);
  apply_proxy_auth(&user, &mut fwd_req);

  let forward_start = Instant::now();
  let stream = match send_request.send_request(fwd_req).await {
    Ok(s) => s,
    Err(e) => {
      warn!("http_upstream: H3 forward request failed: {e}");
      return UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx);
    }
  };

  let (send_stream, mut stream) = stream.split();
  let mut upload = Some(Upload::start(send_stream, req_body, tracker));
  let response = {
    let response = stream.recv_response();
    tokio::pin!(response);
    tokio::select! {
      biased;
      response = &mut response => response,
      result = upload.as_mut().expect("upload started") => {
        if let Err(error) = result { return error.to_response(ctx); }
        upload = None;
        response.await
      }
    }
  };
  let proxy_resp = match response {
    Ok(response) => response,
    Err(error) => {
      return UpstreamError::ConnectionTerminated(error.to_string())
        .to_response(ctx);
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    proxy_resp.status().as_str().to_string(),
  );

  let (parts, ()) = proxy_resp.into_parts();
  forward_response(
    parts,
    ResponseBody::new(H3ResponseBody::new(stream, upload)),
    ctx,
  )
}

type H3ClientRequestStream =
  h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

enum H3ResponseBodyState {
  Data,
  Trailers,
  Done,
}

struct H3ResponseBody {
  stream: H3ClientRequestStream,
  state: H3ResponseBodyState,
  upload: Option<Upload>,
}

impl H3ResponseBody {
  fn new(
    stream: H3ClientRequestStream,
    upload: Option<Upload>,
  ) -> Self {
    Self { stream, state: H3ResponseBodyState::Data, upload }
  }
}

impl Unpin for H3ResponseBody {}

impl Body for H3ResponseBody {
  type Data = Bytes;
  type Error = anyhow::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    if let Some(upload) = &mut this.upload
      && let Poll::Ready(result) = Pin::new(upload).poll(cx)
    {
      this.upload = None;
      if let Err(error) = result {
        this.state = H3ResponseBodyState::Done;
        return Poll::Ready(Some(Err(error.into())));
      }
    }
    loop {
      match this.state {
        H3ResponseBodyState::Data => {
          match this.stream.poll_recv_data(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(Some(mut chunk))) => {
              let bytes = chunk.copy_to_bytes(chunk.remaining());
              return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            Poll::Ready(Ok(None)) => {
              this.state = H3ResponseBodyState::Trailers;
            }
            Poll::Ready(Err(e)) => {
              this.state = H3ResponseBodyState::Done;
              return Poll::Ready(Some(Err(anyhow::anyhow!(
                "H3 response body failed: {e}"
              ))));
            }
          }
        }
        H3ResponseBodyState::Trailers => {
          match this.stream.poll_recv_trailers(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(Some(mut trailers))) => {
              crate::hop_headers::strip_trailer_headers(&mut trailers);
              this.state = H3ResponseBodyState::Done;
              return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            Poll::Ready(Ok(None)) => {
              this.state = H3ResponseBodyState::Done;
              return Poll::Ready(None);
            }
            Poll::Ready(Err(e)) => {
              this.state = H3ResponseBodyState::Done;
              return Poll::Ready(Some(Err(anyhow::anyhow!(
                "H3 response trailers failed: {e}"
              ))));
            }
          }
        }
        H3ResponseBodyState::Done => return Poll::Ready(None),
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    matches!(self.state, H3ResponseBodyState::Done)
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::default()
  }
}

// ============================================================================
// H3 Client (QUIC + H3 to proxy, always proxy mode)
// ============================================================================

pub(crate) struct Http3Client {
  pub(crate) state: Rc<tokio::sync::Mutex<Http3AddressState>>,
  pub(crate) proxy_addr: String,
  pub(crate) hostname: Option<String>,
  pub(crate) tls_handshake_timeout: Duration,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) dns_resolve_timeout: Duration,
  pub(crate) quic: QuicConfig,
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl ClientProtocol for Http3Client {
  fn forward<'a>(
    &'a self,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    let user = self.user.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      let send_request = self.get_connection(&tls, &tracker).await?;

      Ok(
        chain_forward_http3(
          send_request,
          user,
          target,
          req_headers,
          req_body,
          ctx,
          &tracker,
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
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    let user = self.user.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      let mut send_request =
        self.get_connection(&tls, &tracker).await?;

      // ConnectTarget can only come from successful request validation.
      // A fixed CONNECT method with its typed URI must build; panic on
      // an invariant violation rather than hide a programming error in
      // a recoverable HTTP response.
      let mut req = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(target.uri())
        .body(())
        .expect("validated CONNECT target must build an H3 request");

      apply_proxy_auth(&user, &mut req);

      let mut stream =
        send_request.send_request(req).await.map_err(|e| {
          UpstreamError::ConnectionTerminated(e.to_string())
        })?;

      let mut resp = stream.recv_response().await.map_err(|e| {
        UpstreamError::ConnectionTerminated(e.to_string())
      })?;

      let upstream_proxy_status =
        crate::proxy_status::take_proxy_status(resp.headers_mut());

      // RFC 9110 §9.3.6: every 2xx establishes a CONNECT tunnel.
      if !resp.status().is_success() {
        return Err(UpstreamError::UpstreamConnectError {
          status: resp.status(),
          upstream_proxy_status,
        });
      }

      let (sending_stream, receiving_stream) = stream.split();
      Ok(ConnectResult {
        transport: Box::new(crate::h3_stream::H3ClientBidiStream::new(
          sending_stream,
          receiving_stream,
        )),
        upstream_addr: None,
        upstream_proxy_status,
        tunnel_idle_timeout,
      })
    })
  }

  fn close(&self) {
    if let Ok(state) = self.state.try_lock()
      && let Some(conn) = &state.quinn_conn
    {
      conn.close(quinn::VarInt::from_u32(0x100), b"shutdown");
    }
  }
}

impl Http3Client {
  async fn get_connection(
    &self,
    tls: &rustls::ClientConfig,
    tracker: &Rc<StreamTracker>,
  ) -> Result<
    h3_cli::SendRequest<h3_quinn::OpenStreams, Bytes>,
    UpstreamError,
  > {
    // Serialize only connection establishment; requests clone the
    // sender and release the lock before opening their independent
    // streams.
    let mut state = self.state.lock().await;
    if state.is_alive()
      && let Some(sender) = &state.send_request
    {
      return Ok(sender.clone());
    }
    let (connection, sender) = establish_http3_connection(
      &self.proxy_addr,
      self.hostname.as_deref(),
      &self.quic,
      self.tls_handshake_timeout,
      self.dns_resolve_timeout,
      tls,
      tracker,
    )
    .await?;
    state.quinn_conn = Some(connection);
    state.send_request = Some(sender.clone());
    Ok(sender)
  }
}
