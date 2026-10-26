//! module: tcp_connect
//! responsibility: connect TCP candidates under a shared deadline
//! public operations: connect
//! data entities: none
//! tests: tcp_connect_tests.rs

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::address_race::{self, RaceError};

pub(super) async fn connect(
  addresses: Vec<SocketAddr>,
  timeout: Duration,
) -> std::io::Result<TcpStream> {
  address_race::connect(addresses, timeout, TcpStream::connect)
    .await
    .map_err(|error| match error {
      RaceError::NoAddresses => std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "no resolved addresses",
      ),
      RaceError::InvalidDeadline => std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "connect timeout exceeds clock range",
      ),
      RaceError::Timeout => std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "connect timed out",
      ),
      RaceError::Failed(error) => error,
    })
}
