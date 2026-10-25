//! module: tcp_connect
//! responsibilities: race resolved TCP addresses within one connection
//! deadline public operations: connect
//! data entities: none
//! tests: tcp_connect_tests.rs

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

const FALLBACK_DELAY: Duration = Duration::from_secs(1);

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
  let deadline =
    Instant::now().checked_add(timeout).ok_or_else(|| {
      std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "connect timeout exceeds clock range",
      )
    })?;
  let mut addresses = addresses.into_iter();
  let mut attempts = JoinSet::new();
  let mut next_attempt = Instant::now();
  let mut exhausted = false;
  let mut last_error = None;
  loop {
    if Instant::now() >= deadline {
      return Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "connect timed out",
      ));
    }
    if !exhausted
      && (attempts.is_empty() || Instant::now() >= next_attempt)
    {
      match addresses.next() {
        Some(address) => {
          attempts.spawn(TcpStream::connect(address));
          next_attempt = Instant::now() + FALLBACK_DELAY;
        }
        None => exhausted = true,
      }
    }
    if attempts.is_empty() && exhausted {
      return Err(last_error.expect("all connection attempts failed"));
    }
    tokio::select! {
      _ = sleep_until(deadline) => {},
      _ = sleep_until(next_attempt), if !exhausted => {},
      result = attempts.join_next(), if !attempts.is_empty() => {
        match result.expect("connection attempt exists") {
          Ok(Ok(stream)) => return Ok(stream),
          Ok(Err(error)) => last_error = Some(error),
          Err(error) if error.is_panic() => {
            // A connect task panic is a programming error, not a failed
            // address candidate. Resume it instead of trying another
            // address or disguising the panic as an ordinary I/O error.
            std::panic::resume_unwind(error.into_panic());
          },
          Err(error) => return Err(std::io::Error::other(error)),
        }
      }
    }
  }
}
