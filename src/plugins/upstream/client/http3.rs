//! module: plugins::upstream::client::http3
//! responsibility: adapt leased HTTP/3 exchanges to the client
//! contract
//! public operations: Http3Client
//! data entities: H3ClientRequestStream, H3ResponseBodyState,
//! H3ResponseBody, Http3Client, H3Sender
//! tests: http3_tests.rs

mod establish;
mod lease;
mod quic_connect;
#[cfg(test)]
mod quic_connect_tests;
mod session;
mod sessions;
pub(super) use sessions::Store;

use crate::io_progress;
mod read_progress;
#[cfg(test)]
mod session_tests;
mod upload;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use io_progress::SendBuffer;
use session::SessionLease;
pub(super) use session::SessionPool;
use upload::Upload;

use super::connect_request::build_connect_request;
use super::forward::{ForwardClient, forward_request};
use super::protocol::{ClientProtocol, ConnectResult};
use crate::context::RequestContext;
use crate::http_message::{
  Request, RequestBody, Response, ResponseBody,
};
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::task_tracker::TaskTracker;

// ============================================================================
// H3 Forward
// ============================================================================

/// Transport adapter for the shared HTTP forwarding policy.
struct H3Sender<'a> {
  session: &'a SessionPool,
  tls: &'a rustls::ClientConfig,
  tracker: &'a std::sync::Arc<TaskTracker>,
}

impl ForwardClient for H3Sender<'_> {
  async fn send(
    &self,
    mut request: Request,
  ) -> Result<Response, UpstreamError> {
    *request.version_mut() = http::Version::HTTP_3;
    let (parts, body) = request.into_parts();
    exchange(
      self.session,
      self.tls,
      http::Request::from_parts(parts, ()),
      body,
      self.tracker,
    )
    .await
  }
}

/// Exchange a request without applying proxy or origin discovery
/// policy.
pub(super) async fn exchange(
  session: &SessionPool,
  tls: &rustls::ClientConfig,
  request: http::Request<()>,
  req_body: RequestBody,
  tracker: &std::sync::Arc<TaskTracker>,
) -> Result<Response, UpstreamError> {
  let settings = request
    .extensions()
    .get::<super::exchange_timeout::Timeouts>()
    .copied()
    .unwrap_or_default();
  let request_id = request
    .extensions()
    .get::<RequestContext>()
    .and_then(RequestContext::request_id)
    .cloned();
  let (stream, lease, reads) =
    session.open(request, tls, tracker).await?;
  // Snapshot immutable metadata before receiving. h3-quinn 0.0.10
  // temporarily moves its RecvStream into a pending read future;
  // asking recv_id() during that read panics in the dependency.
  let stream_id = stream.id();

  let (send_stream, mut stream) = stream.split();
  let mut upload = Some(Upload::start(
    send_stream,
    req_body,
    tracker,
    request_id.clone(),
    settings.send,
    lease.clone(),
  ));
  let proxy_resp = receive_final_response(
    &mut stream,
    settings.read,
    &mut upload,
    &reads,
    session.limits(),
  )
  .await?;
  let (parts, ()) = proxy_resp.into_parts();
  Ok(Response::from_parts(
    parts,
    ResponseBody::new(H3ResponseBody::new(
      stream,
      stream_id,
      request_id,
      upload,
      lease,
      (settings.read, session.limits()),
      reads,
    )),
  ))
}

type H3ClientRequestStream =
  h3::client::RequestStream<read_progress::Recv, SendBuffer>;

enum H3ResponseBodyState {
  Data,
  Trailers,
  Done,
}

struct H3ResponseBody {
  stream: H3ClientRequestStream,
  stream_id: h3::quic::StreamId,
  request_id: Option<crate::request_id::RequestId>,
  state: H3ResponseBodyState,
  upload: Option<Upload>,
  _lease: SessionLease,
  read_timeout: Duration,
  limits: crate::header_limits::Limits,
  reads: io_progress::Progress,
  read_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl H3ResponseBody {
  fn new(
    stream: H3ClientRequestStream,
    stream_id: h3::quic::StreamId,
    request_id: Option<crate::request_id::RequestId>,
    upload: Option<Upload>,
    lease: SessionLease,
    (read_timeout, limits): (Duration, crate::header_limits::Limits),
    reads: io_progress::Progress,
  ) -> Self {
    Self {
      stream,
      stream_id,
      request_id,
      state: H3ResponseBodyState::Data,
      upload,
      _lease: lease,
      read_timeout,
      limits,
      reads,
      read_timer: None,
    }
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
            Poll::Pending => {
              if this.reads.poll_stalled(
                &mut this.read_timer,
                this.read_timeout,
                cx,
              ) {
                this
                  .stream
                  .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                this.upload = None;
                this.state = H3ResponseBodyState::Done;
                return Poll::Ready(Some(Err(
                  std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream read inactivity timeout",
                  )
                  .into(),
                )));
              }
              return Poll::Pending;
            }
            Poll::Ready(Ok(Some(mut chunk))) => {
              this.read_timer = None;
              let bytes = chunk.copy_to_bytes(chunk.remaining());
              tracing::trace!(request_id = this.request_id.as_ref().map(tracing::field::display), stream_id = %this.stream_id, bytes = bytes.len(), "H3 response content received");
              return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            Poll::Ready(Ok(None)) => {
              tracing::trace!(request_id = this.request_id.as_ref().map(tracing::field::display), stream_id = %this.stream_id, "H3 response content ended");
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
            Poll::Pending => {
              if this.reads.poll_stalled(
                &mut this.read_timer,
                this.read_timeout,
                cx,
              ) {
                this
                  .stream
                  .stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                this.upload = None;
                this.state = H3ResponseBodyState::Done;
                return Poll::Ready(Some(Err(
                  std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "upstream read inactivity timeout",
                  )
                  .into(),
                )));
              }
              return Poll::Pending;
            }
            Poll::Ready(Ok(Some(mut trailers))) => {
              if !this.limits.accepts(&trailers) {
                this.state = H3ResponseBodyState::Done;
                this
                  .stream
                  .stop_sending(h3::error::Code::H3_EXCESSIVE_LOAD);
                return Poll::Ready(Some(Err(anyhow::anyhow!(
                  "too many upstream response trailers"
                ))));
              }
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
  pub(crate) session: SessionPool,
  pub(crate) tunnel_idle_timeout: Duration,
  pub(crate) user: Option<crate::config::UserCredential>,
}

impl ClientProtocol for Http3Client {
  fn forward<'a>(
    &'a self,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a std::sync::Arc<TaskTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>
  {
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      forward_request(
        H3Sender {
          session: &self.session,
          tls: &tls,
          tracker: &tracker,
        },
        &self.user,
        target,
        req_headers,
        req_body,
        ctx,
      )
      .await
    })
  }

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    request: &'a ::http::request::Parts,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a std::sync::Arc<TaskTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  > {
    let tls = tls_config.clone();
    let tracker = tracker.clone();
    let tunnel_idle_timeout = self.tunnel_idle_timeout;
    Box::pin(async move {
      let tls = tls.ok_or_else(|| {
        UpstreamError::TlsCertificateError(
          "no TLS configuration for HTTP/3 upstream".into(),
        )
      })?;

      let mut req = build_connect_request(target, &self.user, request);
      *req.version_mut() = http::Version::HTTP_3;
      let udp =
        request.extensions.get::<crate::connect_udp::request::Udp>();
      if let Some(udp) = udp {
        let mut udp = udp.clone();
        udp.authority = self.session.proxy_authority();
        crate::connect_udp::request::apply(&mut req, &udp, true);
      }

      let settings = req
        .extensions()
        .get::<super::exchange_timeout::Timeouts>()
        .copied()
        .unwrap_or_default();
      let (mut stream, lease, reads) =
        self.session.open(req, &tls, &tracker).await?;

      let mut resp = receive_final_response(
        &mut stream,
        settings.read,
        &mut None,
        &reads,
        self.session.limits(),
      )
      .await?;

      // RFC 9110 §9.3.6: every 2xx establishes a CONNECT tunnel.
      if !resp.status().is_success() {
        return Err(UpstreamError::UpstreamConnectError {
          status: resp.status(),
          upstream_proxy_status: crate::proxy_status::take_proxy_status(
            resp.headers_mut(),
          ),
        });
      }

      if udp.is_some() {
        crate::connect_udp::negotiation::validate_http3_response(
          resp.status(),
          resp.headers(),
        )
        .map_err(|error| {
          UpstreamError::InvalidResponse(error.to_string())
        })?;
      }
      let id = stream.id().into_inner();
      use h3::ConnectionState;
      let enabled = self.session.datagram_enabled()
        && lease.session().sender.settings().enable_datagram();
      let hub = lease.session().datagrams.clone();
      let (sending_stream, receiving_stream) = stream.split();
      let transport: Box<dyn crate::stream::Io> = Box::new(
        lease.attach(crate::h3_stream::H3ClientBidiStream::new(
          sending_stream,
          receiving_stream,
        )),
      );
      let transport = if udp.is_some() {
        hub.attach(transport, id, enabled, &tracker)
      } else {
        transport
      };
      Ok(ConnectResult {
        transport,
        upstream_addr: None,
        upstream_response: Some(resp.into_parts().0),
        tunnel_idle_timeout,
      })
    })
  }
}

/// h3 returns one header section per call, including informational
/// responses. Only a final section determines forwarding or CONNECT
/// success. Read inactivity starts after upload, and each header
/// section is progress. An early response is accepted while upload
/// continues.
async fn receive_final_response<S: h3::quic::RecvStream>(
  stream: &mut h3::client::RequestStream<S, SendBuffer>,
  read_timeout: Duration,
  upload: &mut Option<Upload>,
  reads: &io_progress::Progress,
  limits: crate::header_limits::Limits,
) -> Result<http::Response<()>, UpstreamError> {
  loop {
    let pending = stream.recv_response();
    tokio::pin!(pending);
    let response = if let Some(sending) = upload {
      tokio::select! {
        biased;
        result = &mut pending => result,
        result = sending => {
          result?;
          *upload = None;
          reads.wait(&mut pending, read_timeout).await.map_err(|_| UpstreamError::ConnectionTimeout("upstream read inactivity timeout".into()))?
        }
      }
    } else {
      reads.wait(&mut pending, read_timeout).await.map_err(|_| {
        UpstreamError::ConnectionTimeout(
          "upstream read inactivity timeout".into(),
        )
      })?
    };
    let response = response.map_err(|error| match error {
      h3::error::StreamError::HeaderTooBig { .. } => {
        UpstreamError::InvalidResponse(error.to_string())
      }
      _ => UpstreamError::ConnectionTerminated(error.to_string()),
    })?;
    if !limits.accepts(response.headers()) {
      return Err(UpstreamError::InvalidResponse(
        "too many upstream response headers".into(),
      ));
    }
    if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
      return Err(UpstreamError::TlsProtocolError(
        "HTTP/3 forbids status 101".into(),
      ));
    }
    if !response.status().is_informational() {
      return Ok(response);
    }
  }
}
