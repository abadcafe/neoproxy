//! Black-box tests for independent QUIC listener endpoints.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use super::quic_bind::create_quic_endpoint;

fn configurations() -> (quinn::ServerConfig, quinn::ClientConfig) {
  let _ = rustls::crypto::ring::default_provider().install_default();
  let certificate =
    rcgen::generate_simple_self_signed(vec!["localhost".into()])
      .unwrap();
  let mut roots = rustls::RootCertStore::empty();
  roots.add(certificate.cert.der().clone()).unwrap();
  let server = quinn::ServerConfig::with_single_cert(
    vec![certificate.cert.der().clone()],
    rustls::pki_types::PrivatePkcs8KeyDer::from(
      certificate.key_pair.serialize_der(),
    )
    .into(),
  )
  .unwrap();
  let client =
    quinn::ClientConfig::with_root_certificates(Arc::new(roots))
      .unwrap();
  (server, client)
}

fn available_address(bind: &str) -> SocketAddr {
  UdpSocket::bind(bind).unwrap().local_addr().unwrap()
}

#[tokio::test]
async fn test_create_quic_endpoint_zero_port_has_exclusive_ownership() {
  let (config, _) = configurations();
  let first = create_quic_endpoint(
    "127.0.0.1:0".parse().unwrap(),
    config.clone(),
  )
  .unwrap();
  assert!(
    create_quic_endpoint(first.local_addr().unwrap(), config).is_err()
  );
}

#[tokio::test]
async fn test_create_quic_endpoint_ipv4_workers_bind_same_address() {
  let (config, _) = configurations();
  let first = create_quic_endpoint(
    available_address("127.0.0.1:0"),
    config.clone(),
  )
  .unwrap();
  let address = first.local_addr().unwrap();
  let others: Vec<_> = (0..3)
    .map(|_| create_quic_endpoint(address, config.clone()).unwrap())
    .collect();
  assert!(others.iter().all(|e| e.local_addr().unwrap() == address));
}

#[tokio::test]
async fn test_create_quic_endpoint_ipv6_workers_bind_same_address() {
  let (config, _) = configurations();
  let first =
    create_quic_endpoint(available_address("[::1]:0"), config.clone())
      .unwrap();
  let second =
    create_quic_endpoint(first.local_addr().unwrap(), config).unwrap();
  assert_eq!(first.local_addr().unwrap(), second.local_addr().unwrap());
}

#[tokio::test]
async fn test_create_quic_endpoint_zero_port_binds_independently() {
  let (config, _) = configurations();
  let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
  let first = create_quic_endpoint(address, config.clone()).unwrap();
  let second = create_quic_endpoint(address, config).unwrap();
  assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
}

#[tokio::test]
async fn test_create_quic_endpoint_exclusive_binding_returns_error() {
  let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
  let (config, _) = configurations();
  let result =
    create_quic_endpoint(occupied.local_addr().unwrap(), config);
  assert!(result.is_err());
}

#[tokio::test]
async fn test_create_quic_endpoint_close_preserves_other_endpoint_connection()
 {
  tokio::time::timeout(Duration::from_secs(3), async {
    let (server_config, client_config) = configurations();
    let first = create_quic_endpoint(
      available_address("127.0.0.1:0"),
      server_config.clone(),
    )
    .unwrap();
    let address = first.local_addr().unwrap();
    let second = create_quic_endpoint(address, server_config).unwrap();
    let mut client =
      quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);
    let connect = client.connect(address, "localhost").unwrap();
    let server = async {
      let (incoming, other) = tokio::select! {
        incoming = first.accept() => (incoming.unwrap(), &second),
        incoming = second.accept() => (incoming.unwrap(), &first),
      };
      let connection = incoming.await.unwrap();
      // Closing a different worker's endpoint must not close this
      // established connection or prevent its next stream exchange.
      other.close(0_u32.into(), b"other worker finished");
      other.wait_idle().await;
      let mut stream = connection.accept_uni().await.unwrap();
      assert_eq!(stream.read_to_end(64).await.unwrap(), b"still alive");
      let mut response = connection.open_uni().await.unwrap();
      response.write_all(b"ack").await.unwrap();
      response.finish().unwrap();
      let _ = response.stopped().await.unwrap();
    };
    let exchange = async {
      let connection = connect.await.unwrap();
      let mut stream = connection.open_uni().await.unwrap();
      stream.write_all(b"still alive").await.unwrap();
      stream.finish().unwrap();
      let mut response = connection.accept_uni().await.unwrap();
      assert_eq!(response.read_to_end(64).await.unwrap(), b"ack");
      connection.close(0_u32.into(), b"finished");
    };
    tokio::join!(server, exchange);
  })
  .await
  .unwrap();
}
