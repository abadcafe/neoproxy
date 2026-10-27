//! Public contracts for aggregate worker readiness and notification.
use std::ffi::OsString;
use std::os::unix::net::UnixDatagram;

use crate::shutdown::ShutdownHandle;
use crate::startup::participants;

fn assert_quiet(socket: &UnixDatagram) {
  let mut message = [0; 32];
  assert_eq!(
    socket.recv(&mut message).unwrap_err().kind(),
    std::io::ErrorKind::WouldBlock
  );
}

#[test]
fn test_participants_notify_once_only_after_all_workers_are_ready() {
  let directory = tempfile::tempdir().unwrap();
  let address = directory.path().join("notify");
  let socket = UnixDatagram::bind(&address).unwrap();
  socket.set_nonblocking(true).unwrap();
  let mut workers = participants(
    2,
    Some(address.into_os_string()),
    ShutdownHandle::new(),
  )
  .unwrap();
  workers[0].mark_ready().unwrap();
  assert_quiet(&socket);
  workers[1].mark_ready().unwrap();
  let mut message = [0; 32];
  let count = socket.recv(&mut message).unwrap();
  assert_eq!(&message[..count], b"READY=1");
  drop(workers);
  assert_quiet(&socket);
}

#[test]
fn test_participants_do_not_notify_if_an_unready_worker_stops() {
  let directory = tempfile::tempdir().unwrap();
  let address = directory.path().join("notify");
  let socket = UnixDatagram::bind(&address).unwrap();
  socket.set_nonblocking(true).unwrap();
  let mut workers = participants(
    2,
    Some(address.into_os_string()),
    ShutdownHandle::new(),
  )
  .unwrap();
  drop(workers.pop().unwrap());
  assert!(workers[0].mark_ready().is_err());
  assert_quiet(&socket);
}

#[test]
fn test_participants_do_not_notify_if_a_ready_worker_stops_during_startup()
 {
  let directory = tempfile::tempdir().unwrap();
  let address = directory.path().join("notify");
  let socket = UnixDatagram::bind(&address).unwrap();
  socket.set_nonblocking(true).unwrap();
  let mut workers = participants(
    2,
    Some(address.into_os_string()),
    ShutdownHandle::new(),
  )
  .unwrap();
  workers[1].mark_ready().unwrap();
  drop(workers.pop().unwrap());
  assert!(workers[0].mark_ready().is_err());
  assert_quiet(&socket);
}

#[test]
fn test_participants_do_not_notify_after_shutdown_begins() {
  let directory = tempfile::tempdir().unwrap();
  let address = directory.path().join("notify");
  let socket = UnixDatagram::bind(&address).unwrap();
  socket.set_nonblocking(true).unwrap();
  let shutdown = ShutdownHandle::new();
  let mut workers =
    participants(1, Some(address.into_os_string()), shutdown.clone())
      .unwrap();
  shutdown.shutdown();
  assert!(workers[0].mark_ready().is_err());
  assert_quiet(&socket);
}

#[test]
fn test_participants_without_a_supervisor_socket_can_start_normally() {
  let mut workers =
    participants(2, None, ShutdownHandle::new()).unwrap();
  workers[0].mark_ready().unwrap();
  workers[1].mark_ready().unwrap();
}

#[test]
fn test_participants_reject_invalid_or_missing_notification_targets() {
  for target in
    ["", "relative/socket", "/nonexistent/neoproxy-notify/socket"]
  {
    assert!(
      participants(
        1,
        Some(OsString::from(target)),
        ShutdownHandle::new()
      )
      .is_err()
    );
  }
}

#[test]
fn test_participants_report_notification_failure() {
  let directory = tempfile::tempdir().unwrap();
  let address = directory.path().join("notify");
  let socket = UnixDatagram::bind(&address).unwrap();
  let mut workers = participants(
    1,
    Some(address.into_os_string()),
    ShutdownHandle::new(),
  )
  .unwrap();
  drop(socket);
  assert!(workers[0].mark_ready().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn test_participants_support_linux_abstract_notification_sockets() {
  use std::os::linux::net::SocketAddrExt;
  let directory = tempfile::tempdir().unwrap();
  let name = directory.path().as_os_str();
  let socket = UnixDatagram::bind_addr(
    &std::os::unix::net::SocketAddr::from_abstract_name(
      name.as_encoded_bytes(),
    )
    .unwrap(),
  )
  .unwrap();
  socket.set_nonblocking(true).unwrap();
  let mut target = OsString::from("@");
  target.push(name);
  let mut workers =
    participants(1, Some(target), ShutdownHandle::new()).unwrap();
  workers[0].mark_ready().unwrap();
  let mut message = [0; 32];
  let count = socket.recv(&mut message).unwrap();
  assert_eq!(&message[..count], b"READY=1");
}
