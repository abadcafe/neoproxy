//! module: connection
//! responsibility: drive H3 connections through request and tunnel
//! shutdown public operations: handle_h3_connection
//! data entities: none
//! tests: HTTP/3 shutdown and streaming process tests

use std::net::SocketAddr;
use std::rc::Rc;

use tracing::warn;

use super::accepting_connection::AcceptingConnection;
use super::stream_handler::handle_h3_stream;
use crate::shutdown::ShutdownHandle;
use crate::tracker::StreamTracker;

pub(super) async fn handle_h3_connection(
  connection: quinn::Connection,
  router: crate::server::ServerRouter,
  requests: Rc<StreamTracker>,
  shutdown: ShutdownHandle,
  local_addr: SocketAddr,
  header_deadline: crate::listeners::header_deadline::HeaderDeadline,
  policy: crate::listeners::http_policy::HttpPolicy,
) {
  let client_addr = connection.remote_address();
  // TLS has already checked any presented certificate against this
  // listener's combined CA roots. Request routing only needs presence.
  let client_cert_presented = connection
    .peer_identity()
    .and_then(|identity| {
      identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()
    })
    .is_some_and(|certificates| !certificates.is_empty());
  let controls = crate::h3_io_deadline::Controls::new(
    policy.write_timeout.duration(),
  );
  let backend = AcceptingConnection::new(
    connection.clone(),
    shutdown.clone(),
    controls.clone(),
  );
  let mut builder = h3::server::builder();
  builder.max_field_section_size(u64::from(
    policy.request_limits.limits().bytes(),
  ));
  let mut h3 = tokio::select! {
    biased;
    _ = shutdown.notified() => return,
    result = builder.build(backend) => match result {
      Ok(connection) => connection,
      Err(error) => { warn!("Failed to create H3 connection: {error}"); return; }
    },
  };
  let mut draining = false;
  // The worker's Transport owner retains this driver throughout plugin
  // shutdown, including CONNECT I/O which has left the request tracker.
  // Even when all streams are idle, keep polling H3 to reject new
  // requests and process control frames. Waiting only on QUIC closure
  // would leave those streams undriven. Closing immediately would
  // discard queued GOAWAY/response bytes. Peer closure or the existing
  // second-phase deadline ends the driver.
  loop {
    let result = tokio::select! {
      biased;
      _ = shutdown.notified(), if !draining => {
        draining = true;
        // h3's argument is a count added to the last accepted ID.
        // One means the next request ID: RFC 9114's first rejected
        // stream, not the ID of a request we are already processing.
        // Admission is independently enforced by the backend gate.
        if let Err(error) = h3.shutdown(1).await {
          if !error.is_h3_no_error() { warn!("H3 GOAWAY failed: {error}"); }
          break;
        }
        continue;
      }
      _ = connection.closed() => break,
      result = h3.accept() => result,
    };
    match result {
      Ok(Some(resolver)) => {
        let router = router.clone();
        let controls = controls.clone();
        requests.register(async move {
          match tokio::time::timeout(
            header_deadline.duration(),
            resolver.resolve_request(),
          )
          .await
          {
            Ok(Ok((request, stream))) => {
              let write_control = controls.take(stream.id());
              handle_h3_stream(
                request,
                stream,
                router,
                client_addr,
                local_addr,
                client_cert_presented,
                (policy, write_control),
              )
              .await
            }
            Ok(Err(error)) => {
              warn!("Failed to resolve request: {error}")
            }
            Err(_) => warn!(
              "H3 request headers deadline exceeded from {client_addr}"
            ),
          }
        });
      }
      Ok(None) => {
        // A peer GOAWAY can finish H3 acceptance before the last
        // response is delivered. Preserve the transport until it closes
        // or the worker's second-phase cancellation takes effect.
        let _ = connection.closed().await;
        break;
      }
      Err(error) => {
        if !error.is_h3_no_error() {
          warn!(
            "connection from {client_addr} on {local_addr}: {error}"
          );
        }
        break;
      }
    }
  }
}
