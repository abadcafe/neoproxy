//! TCP socket creation helper for listeners.
//!
//! Provides a shared function for creating TCP listeners with
//! address/port reuse enabled, avoiding code duplication across
//! HTTP, HTTPS, and SOCKS5 listeners.

use std::net::SocketAddr;

use anyhow::Result;

/// Create a TCP listener with SO_REUSEADDR and SO_REUSEPORT enabled.
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
  socket.set_reuseaddr(true)?;
  socket.set_reuseport(true)?;
  socket.bind(addr)?;
  Ok(socket.listen(1024)?)
}
