//! module: tcp_accept
//! responsibilities: recover TCP accept operations according to error
//! scope public operations: accept, accept_tcp, AcceptRetryDelay
//! (configuration) data entities: AcceptRetryDelay, DurationValue,
//! Recovery tests: tcp_accept_tests.rs

use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Result, ensure};
use serde::Deserialize;

const DEFAULT_ACCEPT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Positive, representable delay used after resource or unrecognized
/// I/O failures. Connection-level errors do not incur this delay.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "DurationValue")]
pub(crate) struct AcceptRetryDelay(Duration);

#[derive(Deserialize)]
struct DurationValue(#[serde(with = "humantime_serde")] Duration);

impl TryFrom<DurationValue> for AcceptRetryDelay {
  type Error = anyhow::Error;

  fn try_from(value: DurationValue) -> Result<Self> {
    ensure!(
      !value.0.is_zero()
        && std::time::Instant::now().checked_add(value.0).is_some(),
      "tcp_accept_retry_delay must be positive and representable"
    );
    Ok(Self(value.0))
  }
}

impl Default for AcceptRetryDelay {
  fn default() -> Self {
    Self(DEFAULT_ACCEPT_RETRY_DELAY)
  }
}

/// Apply the same low-latency socket policy to every TCP listener.
pub(super) async fn accept_tcp(
  address: SocketAddr,
  retry_delay: AcceptRetryDelay,
  listener: &tokio::net::TcpListener,
) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
  accept(address, retry_delay, || async {
    let (stream, peer) = listener.accept().await?;
    stream.set_nodelay(true)?;
    Ok((stream, peer))
  })
  .await
}

/// Drive accept until a connection arrives or the listener fails.
/// Callers race this future against shutdown, cancelling both pending
/// I/O and backoff. Accept operation panics intentionally propagate:
/// they are programming failures, not recoverable I/O errors.
pub(crate) async fn accept<T, F>(
  address: SocketAddr,
  retry_delay: AcceptRetryDelay,
  mut next: impl FnMut() -> F,
) -> io::Result<T>
where
  F: Future<Output = io::Result<T>>,
{
  loop {
    match next().await {
      Ok(connection) => return Ok(connection),
      Err(error) => match recovery(&error) {
        Recovery::Retry => {
          tracing::debug!(%address, %error, "accept connection failed; continuing");
          // No timed backoff for a failed pending connection. Yield so
          // repeated ready errors cannot starve shutdown or active I/O.
          tokio::task::yield_now().await;
        }
        Recovery::Backoff => {
          tracing::error!(
            %address, %error, retry_delay = ?retry_delay.0,
            "accept failed; retrying after backoff"
          );
          tokio::time::sleep(retry_delay.0).await;
        }
        Recovery::Fail => {
          tracing::error!(%address, %error, "listener accept failed; stopping listener");
          return Err(error);
        }
      },
    }
  }
}

enum Recovery {
  Retry,
  Backoff,
  Fail,
}

fn recovery(error: &io::Error) -> Recovery {
  if let Some(errno) = error.raw_os_error() {
    match errno {
      libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS => {
        return Recovery::Backoff;
      }
      // An invalid descriptor, socket, listening state or syscall
      // argument cannot be repaired by retrying accept on this
      // listener.
      libc::EBADF | libc::ENOTSOCK | libc::EINVAL | libc::EFAULT => {
        return Recovery::Fail;
      }
      // Linux accept can report errors belonging to the NEW connection.
      // EOPNOTSUPP and EPERM must be checked before ErrorKind, which
      // would suggest an unsupported listener or permission failure.
      // https://man7.org/linux/man-pages/man2/accept.2.html
      #[cfg(target_os = "linux")]
      libc::ENETDOWN
      | libc::EPROTO
      | libc::ENOPROTOOPT
      | libc::EHOSTDOWN
      | libc::ENONET
      | libc::EHOSTUNREACH
      | libc::EOPNOTSUPP
      | libc::ENETUNREACH
      | libc::EPERM
      | libc::ESOCKTNOSUPPORT
      | libc::EPROTONOSUPPORT => return Recovery::Retry,
      _ => {}
    }
  }

  match error.kind() {
    ErrorKind::Interrupted
    | ErrorKind::WouldBlock
    | ErrorKind::ConnectionAborted
    | ErrorKind::ConnectionReset
    | ErrorKind::ConnectionRefused
    | ErrorKind::TimedOut
    | ErrorKind::NetworkDown
    | ErrorKind::NetworkUnreachable
    | ErrorKind::HostUnreachable => Recovery::Retry,
    ErrorKind::InvalidInput | ErrorKind::Unsupported => Recovery::Fail,
    // Unknown I/O failures do not establish that the listener is dead.
    // Keep the error visible and avoid a busy retry loop while allowing
    // recovery, as for resource exhaustion.
    _ => Recovery::Backoff,
  }
}
