//! module: transport_io
//! responsibility: define observed HTTP transport I/O
//! public operations: ProxyIo
//! data entities: none
//! tests: connector_tests.rs, origin_connector_tests.rs
/// The HTTP adapter only needs HTTP I/O and the connected peer
/// identity. Concrete TCP/TLS connectors implement this consumer-owned
/// contract.
pub(super) trait ProxyIo:
  hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static
{
  fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr>;
  fn observation(&self) -> super::observation::ConnectionObservation;
}
