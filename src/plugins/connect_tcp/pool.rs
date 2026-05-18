use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::combinators::UnsyncBoxBody;
use bytes::Bytes;
use tracing::info;

pub(crate) struct TcpPool {
  client: Client<HttpConnector, UnsyncBoxBody<Bytes, anyhow::Error>>,
}

pub(crate) static TCP_POOL: LazyLock<Mutex<Option<TcpPool>>> =
  LazyLock::new(|| Mutex::new(None));

/// Initialize the global TCP connection pool.
///
/// Idempotent: if already initialized, this is a no-op.
pub(crate) fn init_tcp_pool(
  pool_size: usize,
  pool_idle_timeout: Duration,
  connect_timeout: Duration,
) -> Result<()> {
  let mut guard = TCP_POOL.lock().unwrap();

  if guard.is_some() {
    info!("TCP pool already initialized, skipping");
    return Ok(());
  }

  let mut connector = HttpConnector::new();
  connector.set_connect_timeout(Some(connect_timeout));
  let client = Client::builder(TokioExecutor::new())
    .pool_max_idle_per_host(pool_size)
    .pool_idle_timeout(pool_idle_timeout)
    .build(connector);

  *guard = Some(TcpPool { client });

  info!(
    "TCP pool initialized: pool_size={}, pool_idle_timeout={:?}, \
     connect_timeout={:?}",
    pool_size, pool_idle_timeout, connect_timeout
  );

  Ok(())
}

/// Send a request through the global TCP pool.
///
/// Returns the response from the target server.
pub(crate) async fn pool_send_request(
  req: http::Request<UnsyncBoxBody<Bytes, anyhow::Error>>,
) -> Result<http::Response<hyper::body::Incoming>> {
  // Clone the client before releasing the lock so we don't hold a
  // std::sync::Mutex guard across an .await point.
  // Client is Arc-backed and cheap to clone.
  let client = {
    let guard = TCP_POOL.lock().unwrap();
    guard
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("TCP pool not initialized"))?
      .client
      .clone()
  };

  client.request(req).await.map_err(Into::into)
}

/// Shutdown the global TCP connection pool.
pub(crate) fn shutdown_tcp_pool() {
  *TCP_POOL.lock().unwrap() = None;
  info!("TCP pool shut down");
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http_body_util::combinators::UnsyncBoxBody;
  use http_body_util::{BodyExt, Empty};
  use serial_test::serial;

  use super::*;

  fn empty_body() -> UnsyncBoxBody<Bytes, anyhow::Error> {
    UnsyncBoxBody::new(Empty::<Bytes>::new().map_err(Into::into))
  }

  #[test]
  #[serial]
  fn test_init_tcp_pool_succeeds() {
    shutdown_tcp_pool();
    let result =
      init_tcp_pool(32, Duration::from_secs(300), Duration::from_secs(10));
    assert!(result.is_ok());
    shutdown_tcp_pool();
  }

  #[test]
  #[serial]
  fn test_init_tcp_pool_is_idempotent() {
    shutdown_tcp_pool();
    init_tcp_pool(32, Duration::from_secs(300), Duration::from_secs(10))
      .expect("first init");
    // Second call with different params is a no-op, not an error
    let result =
      init_tcp_pool(16, Duration::from_secs(60), Duration::from_secs(5));
    assert!(result.is_ok());
    shutdown_tcp_pool();
  }

  #[test]
  #[serial]
  fn test_shutdown_allows_reinit() {
    shutdown_tcp_pool();
    init_tcp_pool(32, Duration::from_secs(300), Duration::from_secs(10))
      .expect("first init");
    shutdown_tcp_pool();
    let result =
      init_tcp_pool(32, Duration::from_secs(300), Duration::from_secs(10));
    assert!(result.is_ok());
    shutdown_tcp_pool();
  }

  #[tokio::test]
  #[serial]
  async fn test_pool_send_request_not_initialized_returns_error() {
    shutdown_tcp_pool();
    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri("http://127.0.0.1:1/")
      .body(empty_body())
      .unwrap();
    let result = pool_send_request(req).await;
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
      msg.contains("not initialized"),
      "unexpected error message: {msg}"
    );
  }

  #[tokio::test]
  #[serial]
  async fn test_pool_send_request_connection_refused_returns_error() {
    shutdown_tcp_pool();
    init_tcp_pool(32, Duration::from_secs(300), Duration::from_secs(10))
      .expect("pool init");

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let req = http::Request::builder()
      .method(http::Method::GET)
      .uri(format!("http://127.0.0.1:{}/", addr.port()))
      .body(empty_body())
      .unwrap();
    let result = pool_send_request(req).await;
    assert!(result.is_err());
    shutdown_tcp_pool();
  }
}
