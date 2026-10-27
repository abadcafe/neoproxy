use std::sync::Arc;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use super::origin_connector::OriginConnector;
use crate::plugins::http_upstream::config::{
  HttpUpstreamPluginConfig, merge_chain_config,
};

fn connector(address: std::net::SocketAddr) -> OriginConnector {
  let config: HttpUpstreamPluginConfig =
    serde_yaml::from_str("upstreams: [{name: direct}]").unwrap();
  let resolved = merge_chain_config(&config).unwrap();
  let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
    rustls::crypto::ring::default_provider(),
  ))
  .with_safe_default_protocol_versions()
  .unwrap()
  .with_root_certificates(rustls::RootCertStore::empty())
  .with_no_client_auth();
  OriginConnector::new(&resolved["direct"], Arc::new(tls), address)
    .unwrap()
}

#[tokio::test]
async fn test_origin_connector_opens_plain_http_without_tls() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let uri = format!("http://{address}/").parse::<http::Uri>().unwrap();
  let (stream, accepted) =
    tokio::join!(connector(address).oneshot(uri), listener.accept());
  let mut stream = TokioIo::new(stream.unwrap());
  stream.write_all(b"plain HTTP").await.unwrap();
  let mut received = [0; 10];
  accepted.unwrap().0.read_exact(&mut received).await.unwrap();
  assert_eq!(&received, b"plain HTTP");
}

#[tokio::test]
async fn test_origin_connector_rejects_missing_authority() {
  let error = connector("127.0.0.1:1".parse().unwrap())
    .oneshot("/path".parse::<http::Uri>().unwrap())
    .await
    .err()
    .unwrap();
  assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn test_origin_connector_preserves_connection_refused() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  drop(listener);
  let uri = format!("http://{address}/").parse::<http::Uri>().unwrap();
  let error = connector(address).oneshot(uri).await.err().unwrap();
  assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
}
