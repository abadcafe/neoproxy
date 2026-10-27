//! module: tcp_listener_base
//! responsibility: own TCP listener acceptance through connection
//! shutdown public operations: TcpListenerBase::{new, start, stop},
//! TcpConnection data entities: TcpListenerBase, TcpConnection
//! tests: tcp_listener_base_tests.rs

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio::task;
use tokio::task::JoinError;
use tracing::{info, warn};

use super::tcp_accept::{self, AcceptRetryDelay};
use crate::shutdown::{LISTENER_SHUTDOWN_TIMEOUT, ShutdownHandle};
use crate::tracker::StreamTracker;

/// Accepted connection with complete transport metadata.
pub(crate) struct TcpConnection {
  pub(crate) stream: TcpStream,
  pub(crate) peer_addr: SocketAddr,
  pub(crate) local_addr: SocketAddr,
  pub(crate) shutdown: ShutdownHandle,
}

/// Owns TCP sockets, accept tasks and bounded connection shutdown.
pub(crate) struct TcpListenerBase {
  listening_set: Rc<RefCell<task::JoinSet<Result<()>>>>,
  stream_tracker: Rc<StreamTracker>,
  graceful_shutdown_timeout: Duration,
}

impl TcpListenerBase {
  /// Create a new TcpListenerBase with default configuration.
  pub(crate) fn new() -> Self {
    Self {
      listening_set: Rc::new(RefCell::new(task::JoinSet::new())),
      stream_tracker: Rc::new(StreamTracker::new()),
      graceful_shutdown_timeout: LISTENER_SHUTDOWN_TIMEOUT,
    }
  }

  /// Bind every address before accepting any connections. A startup
  /// failure releases all sockets without spawning partial listeners.
  pub(crate) fn start<H, F>(
    &self,
    addresses: &[SocketAddr],
    name: &'static str,
    retry: AcceptRetryDelay,
    handler: H,
  ) -> Result<Pin<Box<dyn Future<Output = Result<()>>>>>
  where
    H: Fn(TcpConnection) -> F + Clone + 'static,
    F: Future<Output = ()> + 'static,
  {
    if self.stream_tracker.shutdown_handle().is_shutdown() {
      return Ok(Box::pin(std::future::ready(Ok(()))));
    }
    let listeners = {
      anyhow::ensure!(
        !addresses.is_empty(),
        "{name} listener requires an address"
      );
      addresses
        .iter()
        .map(|&address| {
          super::tcp_bind::create_tcp_listener(address)
            .with_context(|| format!("{name} bind failed on {address}"))
        })
        .collect::<Result<Vec<_>>>()?
    };
    let tasks = listeners.into_iter().map(|listener| {
      let tracker = self.stream_tracker.clone();
      let shutdown = tracker.shutdown_handle();
      let handler = handler.clone();
      Box::pin(async move {
        let address = listener.local_addr()?;
        info!("{name} listener started on {address}");
        loop {
          let accepted = tokio::select! {
            biased;
            _ = shutdown.notified() => break,
            accepted = tcp_accept::accept_tcp(address, retry, &listener) => accepted,
          };
          let (stream, peer_addr) = accepted
            .with_context(|| format!("{name} accept failed on {address}"))?;
          let local_addr = match stream.local_addr() {
            Ok(address) => address,
            Err(error) => {
              warn!("{name} failed to get local address from {peer_addr}: {error}");
              continue;
            }
          };
          tracker.register(handler(TcpConnection {
            stream, peer_addr, local_addr, shutdown: shutdown.clone(),
          }));
        }
        info!("{name} listener on {address} shutting down");
        Ok(())
      }) as Pin<Box<dyn Future<Output = Result<()>>>>
    });
    Ok(self.start_with_tasks(tasks))
  }

  /// Spawn tasks and return a future that manages their lifecycle.
  ///
  /// Spawns each task into the listening set, then waits for shutdown
  /// notification. After shutdown, joins all tasks and performs
  /// graceful shutdown of the stream tracker.
  fn start_with_tasks<I>(
    &self,
    tasks: I,
  ) -> Pin<Box<dyn Future<Output = Result<()>>>>
  where
    I: IntoIterator<Item = Pin<Box<dyn Future<Output = Result<()>>>>>,
  {
    let listening_set = self.listening_set.clone();
    for task in tasks {
      listening_set.borrow_mut().spawn_local(task);
    }
    let stream_tracker = self.stream_tracker.clone();
    let shutdown = self.stream_tracker.shutdown_handle();
    let graceful_timeout = self.graceful_shutdown_timeout;
    Box::pin(async move {
      let mut failure = None;
      loop {
        tokio::select! {
          _ = shutdown.notified() => break,
          result = join_next(&listening_set), if !listening_set.borrow().is_empty() => {
            match result {
              Some(Ok(Ok(()))) => {},
              Some(Ok(Err(error))) => { failure = Some(error); break; },
              Some(Err(error)) => { failure = Some(error.into()); break; },
              None => break,
            }
          }
        }
      }
      stream_tracker.shutdown();
      while let Some(result) = join_next(&listening_set).await {
        match result {
          Ok(Ok(())) => {}
          Ok(Err(error)) => {
            failure.get_or_insert(error);
          }
          Err(error) => {
            failure.get_or_insert(error.into());
          }
        }
      }
      stream_tracker.graceful_shutdown(graceful_timeout).await;
      match failure {
        Some(error) => Err(error),
        None => Ok(()),
      }
    })
  }

  /// Trigger graceful shutdown.
  pub(crate) fn stop(&self) {
    self.stream_tracker.shutdown()
  }
}

async fn join_next(
  join_set: &RefCell<task::JoinSet<Result<()>>>,
) -> Option<Result<Result<()>, JoinError>> {
  poll_fn(|cx| join_set.borrow_mut().poll_join_next(cx)).await
}
