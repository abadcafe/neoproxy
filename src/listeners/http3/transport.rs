//! module: transport
//! responsibility: retain a worker's QUIC transport until business
//! shutdown completes public operations: Transport::{new, bind, spawn,
//! drain} data entities: Transport
//! tests: HTTP/3 worker/shutdown process tests

use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;

use tracing::warn;

use super::quic_bind::create_quic_endpoint;
use super::quic_config::H3_NO_ERROR_CODE;
use crate::shutdown::SERVICE_SHUTDOWN_TIMEOUT;
use crate::tracker::{ABORT_DRAIN_TIMEOUT, StreamTracker};

pub(super) struct Transport {
  endpoints: RefCell<Vec<quinn::Endpoint>>,
  drivers: StreamTracker,
}

impl Transport {
  pub(super) fn new() -> Self {
    Self {
      endpoints: RefCell::new(Vec::new()),
      drivers: StreamTracker::new(),
    }
  }

  pub(super) fn bind(
    &self,
    address: SocketAddr,
    config: quinn::ServerConfig,
  ) -> std::io::Result<quinn::Endpoint> {
    let endpoint = create_quic_endpoint(address, config)?;
    self.endpoints.borrow_mut().push(endpoint.clone());
    Ok(endpoint)
  }

  pub(super) fn spawn(
    &self,
    driver: impl Future<Output = ()> + 'static,
  ) {
    self.drivers.register(driver);
  }

  pub(super) async fn drain(&self) {
    // Runs concurrently with plugin uninstall in the second phase.
    // Its 3s + 2s budget is not a third serial shutdown period.
    if tokio::time::timeout(SERVICE_SHUTDOWN_TIMEOUT, self.wait_idle())
      .await
      .is_err()
    {
      warn!(
        "HTTP/3 transport shutdown timed out; aborting remaining \
         drivers"
      );
      self.drivers.abort_all();
      if tokio::time::timeout(ABORT_DRAIN_TIMEOUT, self.wait_idle())
        .await
        .is_err()
      {
        warn!("HTTP/3 transport cancellation cleanup timed out");
      }
    }
  }

  async fn wait_idle(&self) {
    self.drivers.wait_shutdown().await;
    let endpoints = self.endpoints.borrow().clone();
    for endpoint in endpoints {
      // Allow CONNECTION_CLOSE and other queued packets to leave the
      // socket before dropping the runtime. This uses the same phase's
      // deadline, including the cancellation cleanup budget.
      endpoint.wait_idle().await;
    }
  }
}

impl Drop for Transport {
  fn drop(&mut self) {
    self.drivers.abort_all();
    // Normal workers drop this owner only after every worker has
    // completed business/driver cleanup. Keep reuseport sockets bound
    // until then; removing a socket earlier can reroute peer traffic.
    for endpoint in self.endpoints.get_mut() {
      endpoint.close(
        quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
        b"worker shutdown complete",
      );
    }
  }
}
