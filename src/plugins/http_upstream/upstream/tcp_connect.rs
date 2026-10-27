//! module: tcp_connect
//! responsibility: establish TCP transports within a connection
//! deadline public operations: connect
//! data entities: none
//! tests: tcp_connect_tests.rs
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

pub(super) async fn connect(
  addresses: Vec<SocketAddr>,
  timeout: Duration,
) -> std::io::Result<TcpStream> {
  if addresses.is_empty() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidInput,
      "no resolved addresses",
    ));
  }
  let deadline = tokio::time::Instant::now()
    .checked_add(timeout)
    .ok_or_else(|| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "connect timeout exceeds clock range",
      )
    })?;
  if timeout.is_zero() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::TimedOut,
      "connect timed out",
    ));
  }
  let mut last_error = None;
  for address in addresses {
    match tokio::time::timeout_at(deadline, TcpStream::connect(address))
      .await
    {
      Ok(Ok(stream)) => {
        stream.set_nodelay(true)?;
        return Ok(stream);
      }
      Ok(Err(error)) => last_error = Some(error),
      Err(_) => {
        return Err(std::io::Error::new(
          std::io::ErrorKind::TimedOut,
          "connect timed out",
        ));
      }
    }
  }
  Err(last_error.expect("nonempty TCP candidate list"))
}
