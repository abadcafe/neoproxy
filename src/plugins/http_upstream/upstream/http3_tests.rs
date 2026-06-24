use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;

use super::http3::{Http3AddressState, Http3Client};
use super::{ClientProtocol, QuicConfig};
use crate::context::RequestContext;
use crate::http_message::{BytesBufBodyWrapper, RequestBody};
use crate::plugins::http_upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

fn quic_config() -> QuicConfig {
  QuicConfig {
    max_idle_timeout: None,
    keep_alive_interval: Duration::from_secs(3),
    max_concurrent_bidi_streams: None,
    initial_mtu: None,
    send_window: None,
    receive_window: None,
  }
}

fn http3_client() -> Http3Client {
  Http3Client {
    state: Rc::new(RefCell::new(Http3AddressState::new())),
    proxy_addr: "127.0.0.1:443".to_string(),
    hostname: None,
    tls_handshake_timeout: Duration::from_millis(100),
    tunnel_idle_timeout: Duration::from_secs(30),
    dns_resolve_timeout: Duration::from_millis(100),
    quic: quic_config(),
    user: None,
  }
}

#[test]
fn test_http3_address_state_new_is_not_alive() {
  let state = Http3AddressState::new();

  assert!(!state.is_alive());
}

#[tokio::test]
async fn test_http3_client_forward_without_tls_config_is_rejected() {
  let client = http3_client();
  let tracker = Rc::new(StreamTracker::new());
  let ctx = RequestContext::new();
  let req = http::Request::builder()
    .method(http::Method::GET)
    .uri("https://example.com/")
    .body(RequestBody::new(BytesBufBodyWrapper::new(
      Empty::<Bytes>::new(),
    )))
    .unwrap();
  let (parts, body) = req.into_parts();

  let result = client.forward(&None, &tracker, parts, body, &ctx).await;

  assert!(matches!(result, Err(UpstreamError::TlsCertificateError(_))));
}

#[tokio::test]
async fn test_http3_client_tunnel_without_tls_config_is_rejected() {
  let client = http3_client();
  let tracker = Rc::new(StreamTracker::new());

  let result =
    client.connect_for_tunnel("example.com:443", &None, &tracker).await;

  assert!(matches!(result, Err(UpstreamError::TlsCertificateError(_))));
}
