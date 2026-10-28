//! module: protocol
//! responsibilities: define upstream forwarding and tunnel transport
//! contracts public operations: ClientProtocol, ConnectResult,
//! QuicConfig data entities: ConnectResult, QuicConfig
//! tests: upstream client black-box tests
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

/// Runtime QUIC configuration, copied from config at construction time.
#[derive(Clone, Debug)]
pub(crate) struct QuicConfig {
  pub(crate) max_idle_timeout: Option<Duration>,
  pub(crate) keep_alive_interval: Duration,
  pub(crate) max_concurrent_bidi_streams: Option<u64>,
  pub(crate) initial_mtu: Option<u16>,
  pub(crate) send_window: Option<u64>,
  pub(crate) receive_window: Option<u64>,
  pub(crate) stream_receive_window: Option<u64>,
}

// ============================================================================
// Client Protocol Trait — abstraction over HTTP/HTTPS/H3 upstream
// clients
// ============================================================================

/// Unified interface for forwarding requests and establishing tunnels,
/// implemented by each protocol variant (Http, Https, H3).
pub(crate) trait ClientProtocol {
  fn forward<'a>(
    &'a self,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
    target: &'a ForwardTarget,
    req_headers: ::http::request::Parts,
    req_body: RequestBody,
    ctx: &'a RequestContext,
  ) -> Pin<Box<dyn Future<Output = Result<Response, UpstreamError>> + 'a>>;

  fn connect_for_tunnel<'a>(
    &'a self,
    target: &'a ConnectTarget,
    request: &'a ::http::request::Parts,
    tls_config: &'a Option<Arc<rustls::ClientConfig>>,
    tracker: &'a Rc<StreamTracker>,
  ) -> Pin<
    Box<dyn Future<Output = Result<ConnectResult, UpstreamError>> + 'a>,
  >;

  /// Close any held connections (QUIC, etc.). Default is no-op.
  fn close(&self) {}
}

pub(crate) struct ConnectResult {
  pub(crate) transport: Box<dyn crate::stream::Io>,
  pub(crate) upstream_addr: Option<std::net::SocketAddr>,
  pub(crate) upstream_response: Option<::http::response::Parts>,
  pub(crate) tunnel_idle_timeout: Duration,
}
