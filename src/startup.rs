//! module: startup
//! responsibility: report aggregate worker startup to a supervisor
//! public operations: participants, WorkerReadiness::mark_ready
//! data entities: WorkerReadiness, Group, State, Phase
//! tests: startup_tests.rs
use std::ffi::OsString;
use std::io;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::{Arc, Mutex};

use crate::shutdown::ShutdownHandle;

pub(crate) struct WorkerReadiness {
  group: Arc<Group>,
  ready: bool,
}
struct Group {
  state: Mutex<State>,
  shutdown: ShutdownHandle,
}
struct State {
  pending: usize,
  phase: Phase,
  notification: Option<UnixDatagram>,
}
enum Phase {
  Starting,
  Ready,
  Failed,
}

pub(crate) fn participants(
  count: usize,
  target: Option<OsString>,
  shutdown: ShutdownHandle,
) -> io::Result<Vec<WorkerReadiness>> {
  let notification = target.map(connect_notification).transpose()?;
  let group = Arc::new(Group {
    state: Mutex::new(State {
      pending: count,
      phase: Phase::Starting,
      notification,
    }),
    shutdown,
  });
  Ok(
    (0..count)
      .map(|_| WorkerReadiness { group: group.clone(), ready: false })
      .collect(),
  )
}

impl WorkerReadiness {
  pub(crate) fn mark_ready(&mut self) -> io::Result<()> {
    assert!(!self.ready, "a worker reports startup exactly once");
    let mut state =
      self.group.state.lock().expect("startup lock poisoned");
    if self.group.shutdown.is_shutdown()
      || matches!(state.phase, Phase::Failed)
    {
      state.phase = Phase::Failed;
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "startup was interrupted",
      ));
    }
    self.ready = true;
    state.pending -= 1;
    if state.pending == 0 {
      if let Some(socket) = state.notification.take()
        && let Err(error) = socket.send(b"READY=1")
      {
        state.phase = Phase::Failed;
        return Err(error);
      }
      state.phase = Phase::Ready;
      tracing::info!("all workers and listeners ready");
    }
    Ok(())
  }
}

impl Drop for WorkerReadiness {
  fn drop(&mut self) {
    let mut state =
      self.group.state.lock().expect("startup lock poisoned");
    if matches!(state.phase, Phase::Starting) {
      state.phase = Phase::Failed;
    }
  }
}

fn connect_notification(target: OsString) -> io::Result<UnixDatagram> {
  let bytes = target.as_encoded_bytes();
  let address = if bytes.starts_with(b"/") {
    SocketAddr::from_pathname(&target)?
  } else if bytes.starts_with(b"@") && bytes.len() > 1 {
    #[cfg(target_os = "linux")]
    {
      use std::os::linux::net::SocketAddrExt;
      SocketAddr::from_abstract_name(&bytes[1..])?
    }
    #[cfg(not(target_os = "linux"))]
    {
      return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "abstract notification sockets require Linux",
      ));
    }
  } else {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "NOTIFY_SOCKET must be an absolute or abstract Unix socket \
       address",
    ));
  };
  let socket = UnixDatagram::unbound()?;
  socket.set_nonblocking(true)?;
  socket.connect_addr(&address)?;
  Ok(socket)
}
