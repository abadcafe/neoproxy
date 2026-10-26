//! module: listeners::tcp_bind
//! responsibility: bind worker-owned reusable TCP listening sockets
//! public operations: create_tcp_listener
//! data entities: none
//! tests: tcp_bind_tests.rs

//! TCP socket creation helper for listeners.
//!
//! Provides a shared function for creating TCP listeners with
//! address/port reuse enabled, avoiding code duplication across
//! HTTP, HTTPS, and SOCKS5 listeners.

use std::net::SocketAddr;

use anyhow::Result;

/// Share explicitly configured ports across workers. Port zero asks
/// for independent allocation and therefore keeps exclusive ownership.
///
/// This function creates a TCP socket, sets reuse options, binds to the
/// given address, and starts listening with a backlog of 1024.
///
/// # Errors
///
/// Returns an error if:
/// - Socket creation fails (e.g., unsupported address family)
/// - Setting socket options fails
/// - Binding to the address fails
/// - Listening fails
pub(crate) fn create_tcp_listener(
  addr: SocketAddr,
) -> Result<tokio::net::TcpListener> {
  let socket = match addr {
    SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
    SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
  };
  let shared = addr.port() != 0;
  socket.set_reuseaddr(shared)?;
  socket.set_reuseport(shared)?;
  socket.bind(addr)?;
  Ok(socket.listen(1024)?)
}
