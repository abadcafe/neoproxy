use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h3::client as h3_cli;
use http_body_util::BodyExt;
use tracing::{info, warn};

use super::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::context::get_server_id;
use crate::http_utils::{
  RequestBody, Response, ResponseBody, append_proxy_status,
  build_error_response, build_proxy_status_with_status,
};
use crate::plugins::http_upstream::error::{
  UpstreamError, classify_quic_error,
};
use crate::plugins::http_upstream::target_parser;
use crate::tracker::StreamTracker;

// ============================================================================
// HTTP/3 Address State
// ============================================================================

/// Per-address H3 connection state, shared across requests via
/// Rc<RefCell>.
pub(crate) struct Http3AddressState {
  pub(crate) quinn_conn: Option<quinn::Connection>,
  pub(crate) send_request:
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
use super::QuicConfig;
use super::utils::{apply_proxy_auth, resolve_address};

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

  let mut cli_endpoint = quinn::Endpoint::client(
    "[::]:0".parse().unwrap(),
  )
  .map_err(|e| {
    UpstreamError::ProxyInternalError(format!(
      "failed to create QUIC endpoint: {e}"
    ))
  })?;

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

  cli_endpoint.set_default_client_config(cli_config);

  let addr =
    tokio::time::timeout(dns_timeout, resolve_address(address))
      .await
      .map_err(|_| {
        UpstreamError::DnsError(format!(
          "DNS resolve for '{address}' timed out"
        ))
      })?
      .map_err(|e| classify_quic_error(e))?;
  let host: &str = hostname.unwrap_or_else(|| {
    address.split_at(address.rfind(':').unwrap_or(address.len())).0
  });
  let connecting = cli_endpoint
    .connect(addr, host)
    .map_err(|e| classify_quic_error(e.into()))?;
  let conn = tokio::time::timeout(tls_handshake_timeout, async {
    connecting.await.map_err(|e| classify_quic_error(e.into()))
  })
  .await
  .map_err(|_| {
    UpstreamError::ConnectionTimeout(format!(
      "QUIC handshake with {address} timed out"
    ))
  })??;

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
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Response {
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

  let mut fwd_req = http::Request::builder()
    .method(req_headers.method.clone())
    .uri(req_headers.uri.clone())
    .body(())
    .unwrap();

  let mut headers = req_headers.headers.clone();
  target_parser::strip_hop_by_hop_headers(&mut headers);
  apply_proxy_auth(&user, &mut fwd_req);

  for (name, value) in headers.iter() {
    fwd_req.headers_mut().insert(name.clone(), value.clone());
  }

  let forward_start = Instant::now();
  let mut stream = match send_request.send_request(fwd_req).await {
    Ok(s) => s,
    Err(e) => {
      warn!("http_upstream: H3 forward request failed: {e}");
      return UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx);
    }
  };

  if !body_bytes.is_empty() {
    if let Err(e) = stream.send_data(body_bytes).await {
      warn!("http_upstream: H3 failed to send body: {e}");
      return UpstreamError::ProxyInternalError(format!(
        "Failed to send request body: {e}"
      ))
      .to_response(ctx);
    }
  }

  if let Err(e) = stream.finish().await {
    warn!("http_upstream: H3 failed to finish request: {e}");
    return UpstreamError::ProxyInternalError(format!(
      "Failed to finish request: {e}"
    ))
    .to_response(ctx);
  }

  let proxy_resp = match stream.recv_response().await {
    Ok(resp) => resp,
    Err(e) => {
      warn!("http_upstream: H3 failed to receive response: {e}");
      return UpstreamError::ConnectionTerminated(e.to_string())
        .to_response(ctx);
    }
  };
  let forward_ms = forward_start.elapsed().as_millis() as u64;

  ctx.insert("upstream.forward_ms", forward_ms.to_string());
  ctx.insert(
    "upstream.forward_status",
    proxy_resp.status().as_str().to_string(),
  );

  let (resp_parts, _) = proxy_resp.into_parts();
  let mut resp_headers = resp_parts.headers;
  target_parser::strip_hop_by_hop_headers(&mut resp_headers);

  let upstream_ps = resp_headers
    .get(http::header::HeaderName::from_static("proxy-status"))
    .cloned();
  resp_headers
    .remove(http::header::HeaderName::from_static("proxy-status"));

  let mut body_buf = bytes::BytesMut::new();
  loop {
    match stream.recv_data().await {
      Ok(Some(mut chunk)) => {
        let b = chunk.copy_to_bytes(chunk.remaining());
        body_buf.extend_from_slice(&b);
      }
      Ok(None) => break,
      Err(e) => {
        warn!("http_upstream: H3 failed to receive response body: {e}");
        break;
      }
    }
  }
  let body_bytes = body_buf.freeze();

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

  let resp_body_wrapped = crate::http_utils::BytesBufBodyWrapper::new(
    http_body_util::Full::new(body_bytes),
  );
  let resp_body = ResponseBody::new(resp_body_wrapped);

  match resp.body(resp_body) {
    Ok(r) => r,
    Err(e) => {
      warn!("http_upstream: failed to build H3 response: {e}");
      build_error_response(
        http::StatusCode::BAD_GATEWAY,
        "Failed to build response",
      )
    }
  }
}

// ============================================================================
// H3 Client (QUIC + H3 to proxy, always proxy mode)
// ============================================================================

pub(crate) struct Http3Client {
  pub(crate) state: Rc<RefCell<Http3AddressState>>,
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
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    let state = self.state.clone();
    let proxy_addr = self.proxy_addr.clone();
    let hostname = self.hostname.clone();
    let quic = self.quic.clone();
    let tls_handshake_timeout = self.tls_handshake_timeout;
    let dns_resolve_timeout = self.dns_resolve_timeout;
    let user = self.user.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      let send_request = if state.borrow().is_alive() {
        state.borrow().send_request.clone().unwrap()
      } else {
        let (quinn_conn, sr) = establish_http3_connection(
          &proxy_addr,
          hostname.as_deref(),
          &quic,
          tls_handshake_timeout,
          dns_resolve_timeout,
          &tls,
          &tracker,
        )
        .await?;
        let mut s = state.borrow_mut();
        s.quinn_conn = Some(quinn_conn);
        s.send_request = Some(sr.clone());
        sr
      };

      Ok(
        chain_forward_http3(
          send_request,
          user,
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
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    let state = self.state.clone();
    let proxy_addr = self.proxy_addr.clone();
    let hostname = self.hostname.clone();
    let tls_handshake_timeout = self.tls_handshake_timeout;
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    let dns_resolve_timeout = self.dns_resolve_timeout;
    let quic = self.quic.clone();
    let user = self.user.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      let mut send_request = if state.borrow().is_alive() {
        state.borrow().send_request.clone().unwrap()
      } else {
        let (quinn_conn, sr) = establish_http3_connection(
          &proxy_addr,
          hostname.as_deref(),
          &quic,
          tls_handshake_timeout,
          dns_resolve_timeout,
          &tls,
          &tracker,
        )
        .await?;
        let mut s = state.borrow_mut();
        s.quinn_conn = Some(quinn_conn);
        s.send_request = Some(sr.clone());
        sr
      };

      let mut req = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(&target)
        .body(())
        .map_err(|e| {
          UpstreamError::ProxyInternalError(e.to_string())
        })?;

      apply_proxy_auth(&user, &mut req);

      let mut stream =
        send_request.send_request(req).await.map_err(|e| {
          UpstreamError::ConnectionTerminated(e.to_string())
        })?;

      let resp = stream.recv_response().await.map_err(|e| {
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
    if let Some(ref conn) = self.state.borrow().quinn_conn {
      conn.close(quinn::VarInt::from_u32(0x100), b"shutdown");
    }
  }
}
