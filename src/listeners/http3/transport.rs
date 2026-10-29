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
use crate::shutdown::ShutdownHandle;
use crate::task_tracker::{ABORT_DRAIN_TIMEOUT, TaskTracker};

pub(super) struct Transport {
  endpoints: RefCell<Vec<quinn::Endpoint>>,
  drivers: TaskTracker,
}

impl Transport {
  pub(super) fn new() -> Self {
    Self {
      endpoints: RefCell::new(Vec::new()),
      drivers: TaskTracker::new(),
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

  pub(super) fn datagrams(
    &self,
    connection: quinn::Connection,
  ) -> crate::connect_udp::h3::Hub {
    crate::connect_udp::h3::Hub::new(connection, &self.drivers)
  }

  pub(super) fn spawn(
    &self,
    driver: impl Future<Output = ()> + 'static,
  ) {
    self.drivers.register(driver);
  }

  pub(super) fn shutdown_handle(&self) -> ShutdownHandle {
    self.drivers.shutdown_handle()
  }

  pub(super) async fn drain(&self, deadline: tokio::time::Instant) {
    self.drivers.shutdown();
    // Plugin cleanup has finished. Use the remainder of its shared
    // phase deadline, retaining QUIC long enough to deliver queued
    // data.
    if tokio::time::timeout_at(deadline, self.wait_idle())
      .await
      .is_err()
    {
      // Request/tunnel cleanup has completed. Explicitly close QUIC
      // and let drivers process closure before resorting to abort.
      for endpoint in self.endpoints.borrow().iter() {
        endpoint.close(
          quinn::VarInt::from_u32(H3_NO_ERROR_CODE),
          b"listener shutdown",
        );
      }
      if tokio::time::timeout(ABORT_DRAIN_TIMEOUT, self.wait_idle())
        .await
        .is_err()
      {
        warn!(
          "HTTP/3 transport cleanup timed out; aborting remaining \
           drivers"
        );
        self.drivers.abort_all();
        self.drivers.drain().await;
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
