//! Black-box tests of TCP accept recovery through the shared driver.

use std::collections::VecDeque;
use std::future::{Ready, ready};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;

use super::tcp_accept::{AcceptRetryDelay, accept};

fn address() -> SocketAddr {
  "127.0.0.1:1234".parse().unwrap()
}

fn source(
  errors: impl IntoIterator<Item = io::Error>,
) -> impl FnMut() -> Ready<io::Result<u8>> {
  let mut outcomes: VecDeque<_> =
    errors.into_iter().map(Err).chain(std::iter::once(Ok(7))).collect();
  move || ready(outcomes.pop_front().expect("unexpected accept call"))
}

#[tokio::test(start_paused = true)]
async fn test_accept_success_returns_without_backoff() {
  let start = tokio::time::Instant::now();
  let result = accept(address(), Default::default(), source([])).await;
  assert_eq!(result.unwrap(), 7);
  assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn test_accept_connection_errors_retry_without_backoff() {
  for kind in [
    ErrorKind::Interrupted,
    ErrorKind::WouldBlock,
    ErrorKind::ConnectionAborted,
    ErrorKind::ConnectionReset,
    ErrorKind::ConnectionRefused,
    ErrorKind::TimedOut,
    ErrorKind::NetworkDown,
    ErrorKind::NetworkUnreachable,
    ErrorKind::HostUnreachable,
  ] {
    let start = tokio::time::Instant::now();
    let result = accept(
      address(),
      Default::default(),
      source([io::Error::from(kind)]),
    )
    .await;
    assert_eq!(result.unwrap(), 7, "{kind:?}");
    assert_eq!(start.elapsed(), Duration::ZERO, "{kind:?}");
  }
}

#[cfg(target_os = "linux")]
#[tokio::test(start_paused = true)]
async fn test_accept_linux_pending_network_errors_retry_without_backoff()
 {
  // Linux may return these errors for the pending connection rather
  // than the listening socket. In particular EOPNOTSUPP must not be
  // misclassified through ErrorKind::Unsupported, nor EPERM through
  // PermissionDenied (firewall rejection).
  for errno in [
    libc::ECONNABORTED,
    libc::ECONNRESET,
    libc::EINTR,
    libc::EAGAIN,
    libc::ENETDOWN,
    libc::EPROTO,
    libc::ENOPROTOOPT,
    libc::EHOSTDOWN,
    libc::ENONET,
    libc::EHOSTUNREACH,
    libc::EOPNOTSUPP,
    libc::ENETUNREACH,
    libc::EPERM,
    libc::ETIMEDOUT,
    libc::ESOCKTNOSUPPORT,
    libc::EPROTONOSUPPORT,
  ] {
    let start = tokio::time::Instant::now();
    let result = accept(
      address(),
      Default::default(),
      source([io::Error::from_raw_os_error(errno)]),
    )
    .await;
    assert_eq!(result.unwrap(), 7, "errno={errno}");
    assert_eq!(start.elapsed(), Duration::ZERO, "errno={errno}");
  }
}

#[tokio::test(start_paused = true)]
async fn test_accept_resource_errors_back_off_one_second_by_default() {
  for errno in [libc::EMFILE, libc::ENFILE, libc::ENOMEM, libc::ENOBUFS]
  {
    let start = tokio::time::Instant::now();
    let result = accept(
      address(),
      Default::default(),
      source([io::Error::from_raw_os_error(errno)]),
    )
    .await;
    assert_eq!(result.unwrap(), 7, "errno={errno}");
    assert_eq!(start.elapsed(), Duration::from_secs(1));
  }
}

#[tokio::test(start_paused = true)]
async fn test_accept_resource_error_uses_configured_backoff() {
  let delay =
    serde_yaml::from_str::<AcceptRetryDelay>("250ms").unwrap();
  let start = tokio::time::Instant::now();
  let result = accept(
    address(),
    delay,
    source([io::Error::from_raw_os_error(libc::EMFILE)]),
  )
  .await;
  assert_eq!(result.unwrap(), 7);
  assert_eq!(start.elapsed(), Duration::from_millis(250));
}

#[tokio::test(start_paused = true)]
async fn test_accept_consecutive_resource_errors_each_back_off() {
  let errors =
    (0..3).map(|_| io::Error::from_raw_os_error(libc::EMFILE));
  let start = tokio::time::Instant::now();
  let result =
    accept(address(), Default::default(), source(errors)).await;
  assert_eq!(result.unwrap(), 7);
  assert_eq!(start.elapsed(), Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn test_accept_listener_failure_returns_original_error_without_retry()
 {
  for errno in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EFAULT]
  {
    let start = tokio::time::Instant::now();
    let result = accept(
      address(),
      Default::default(),
      source([io::Error::from_raw_os_error(errno)]),
    )
    .await;
    assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
    assert_eq!(start.elapsed(), Duration::ZERO);
  }
}

#[tokio::test(start_paused = true)]
async fn test_accept_invalid_operation_returns_error_without_retry() {
  for kind in [ErrorKind::InvalidInput, ErrorKind::Unsupported] {
    let start = tokio::time::Instant::now();
    let result = accept(
      address(),
      Default::default(),
      source([io::Error::from(kind)]),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), kind);
    assert_eq!(start.elapsed(), Duration::ZERO);
  }
}

#[tokio::test(start_paused = true)]
async fn test_accept_unrecognized_os_error_backs_off() {
  let start = tokio::time::Instant::now();
  let result = accept(
    address(),
    Default::default(),
    source([io::Error::from_raw_os_error(libc::EIO)]),
  )
  .await;
  assert_eq!(result.unwrap(), 7);
  assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn test_accept_unknown_io_error_backs_off() {
  let start = tokio::time::Instant::now();
  let result = accept(
    address(),
    Default::default(),
    source([io::Error::other("unrecognized accept failure")]),
  )
  .await;
  assert_eq!(result.unwrap(), 7);
  assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[test]
fn test_accept_retry_delay_rejects_invalid_durations() {
  for value in ["0s", "-1s", "invalid", "18446744073709551615s"] {
    assert!(serde_yaml::from_str::<AcceptRetryDelay>(value).is_err());
  }
}

#[tokio::test(start_paused = true)]
async fn test_accept_shutdown_interrupts_resource_backoff() {
  let shutdown = crate::shutdown::ShutdownHandle::new();
  let wait = accept(
    address(),
    Default::default(),
    source([io::Error::from_raw_os_error(libc::EMFILE)]),
  );
  tokio::pin!(wait);
  assert!(futures::poll!(&mut wait).is_pending());
  shutdown.shutdown();
  let start = tokio::time::Instant::now();
  tokio::select! {
    _ = &mut wait => panic!("shutdown must interrupt accept backoff"),
    _ = shutdown.notified() => {},
  }
  assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn test_accept_shutdown_interrupts_continuous_connection_errors()
{
  let shutdown = crate::shutdown::ShutdownHandle::new();
  let wait = accept(address(), Default::default(), || {
    ready(Err::<u8, _>(io::Error::from(ErrorKind::ConnectionAborted)))
  });
  tokio::pin!(wait);
  assert!(futures::poll!(&mut wait).is_pending());
  shutdown.shutdown();
  let start = tokio::time::Instant::now();
  tokio::select! {
    _ = &mut wait => panic!("shutdown must interrupt repeated accept errors"),
    _ = shutdown.notified() => {},
  }
  assert_eq!(start.elapsed(), Duration::ZERO);
}
#[tokio::test]
async fn test_accept_tcp_disables_nagle_for_interactive_proxy_traffic()
{
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let (accepted, client) = tokio::join!(
    super::tcp_accept::accept_tcp(
      address,
      Default::default(),
      &listener
    ),
    tokio::net::TcpStream::connect(address),
  );
  let (stream, _) = accepted.unwrap();
  assert!(client.is_ok());
  assert!(stream.nodelay().unwrap());
}
