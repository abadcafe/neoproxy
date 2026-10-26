//! module: quic_bind
//! responsibility: create a worker-owned QUIC listener endpoint
//! public operations: create_quic_endpoint
//! data entities: none
//! tests: quic_bind_tests.rs

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

/// Bind an independent endpoint to the current worker's Tokio runtime.
pub(super) fn create_quic_endpoint(
  address: SocketAddr,
  mut config: quinn::ServerConfig,
) -> io::Result<quinn::Endpoint> {
  // Like TCP listeners, workers bind distinct sockets to the same
  // explicit address. Set reuse options before binding; Quinn's
  // Endpoint::server uses a plain UdpSocket::bind without SO_REUSEPORT.
  let socket = Socket::new(
    Domain::for_address(address),
    Type::DGRAM,
    Some(Protocol::UDP),
  )?;
  // Ephemeral allocation must exclude sockets already bound by any
  // endpoint, even those allowing reuse. Otherwise independent port-0
  // endpoints can accidentally enter the same reuseport group.
  let shared = address.port() != 0;
  socket.set_reuse_address(shared)?;
  socket.set_reuse_port(shared)?;
  socket.set_nonblocking(true)?;
  socket.bind(&address.into())?;

  // Kernel reuseport routing does not track QUIC connection IDs.
  // Address changes need not preserve connections in this project;
  // advertise that active migration is disabled. Each worker owns its
  // endpoint and can close only its own connections during shutdown.
  config.migration(false);
  quinn::Endpoint::new(
    quinn::EndpointConfig::default(),
    Some(config),
    socket.into(),
    Arc::new(quinn::TokioRuntime),
  )
}
