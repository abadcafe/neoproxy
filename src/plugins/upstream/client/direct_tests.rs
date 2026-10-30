use std::time::Duration;

use super::direct::DirectClient;
use super::protocol::ClientProtocol;
use crate::plugins::upstream::target_parser::parse_connect_target;
use crate::task_tracker::TaskTracker;

#[tokio::test]
async fn test_http_client_direct_tunnel_connects_to_target() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let config: crate::plugins::upstream::config::UpstreamPluginConfig =
    serde_yaml::from_str(
      "upstreams: [{name: direct, tunnel_idle_timeout: 30s}]",
    )
    .unwrap();
  let upstreams =
    crate::plugins::upstream::config::merge_chain_config(&config)
      .unwrap();
  let tls = rustls::ClientConfig::builder_with_provider(
    std::sync::Arc::new(rustls::crypto::ring::default_provider()),
  )
  .with_safe_default_protocol_versions()
  .unwrap()
  .with_root_certificates(rustls::RootCertStore::empty())
  .with_no_client_auth();
  let pools =
    super::ConnectionPools::new(std::collections::HashMap::from([(
      "default".into(),
      Default::default(),
    )]))
    .unwrap();
  let http_client = DirectClient::new(
    &upstreams["direct"],
    std::sync::Arc::new(tls),
    addr,
    std::rc::Rc::new(crate::task_tracker::TaskTracker::new()),
    pools.get("default"),
  )
  .unwrap();
  let tracker = std::rc::Rc::new(TaskTracker::new());

  let accept = async {
    let (_stream, peer) = listener.accept().await.unwrap();
    peer
  };
  let request = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(addr.to_string())
    .body(())
    .unwrap();
  let (parts, ()) = request.into_parts();
  let target = parse_connect_target(&parts).unwrap();
  let (result, peer) = tokio::join!(
    http_client.connect_for_tunnel(&target, &parts, &None, &tracker),
    accept
  );
  let result = result.unwrap();

  assert_eq!(result.upstream_addr.map(|a| a.ip()), Some(peer.ip()));
  assert!(result.upstream_response.is_none());
  assert_eq!(result.tunnel_idle_timeout, Duration::from_secs(30));
}
