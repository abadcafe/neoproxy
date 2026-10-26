//! Shared TCP listener base for lifecycle management.
//!
//! Provides [`TcpListenerBase`] which encapsulates the common lifecycle
//! pattern shared by HTTP and HTTPS listeners: JoinSet management,
//! stream tracking, and graceful shutdown.
//!
//! module: tcp_listener_base
//! responsibilities: manage TCP listener lifecycle
//! public operations: TcpListenerBase lifecycle methods
//! data entities: TcpListenerBase
//! tests: tcp_listener_base_tests.rs

use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Result;
use tokio::task;
use tokio::task::JoinError;

use crate::shutdown::LISTENER_SHUTDOWN_TIMEOUT;
use crate::tracker::StreamTracker;

/// Shared base for TCP-based listeners.
///
/// Manages the listener JoinSet, stream tracker, and graceful shutdown
/// lifecycle. Protocol-specific listeners (HTTP, HTTPS) delegate
/// lifecycle management to this base while keeping their own accept
/// loop logic.
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

  /// Spawn tasks and return a future that manages their lifecycle.
  ///
  /// Spawns each task into the listening set, then waits for shutdown
  /// notification. After shutdown, joins all tasks and performs
  /// graceful shutdown of the stream tracker.
  pub(crate) fn start_with_tasks<I>(
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

  /// Get a shutdown handle for use in accept loops.
  pub(crate) fn shutdown_handle(
    &self,
  ) -> crate::shutdown::ShutdownHandle {
    self.stream_tracker.shutdown_handle()
  }

  /// Get a clone of the stream tracker.
  pub(crate) fn stream_tracker(&self) -> Rc<StreamTracker> {
    self.stream_tracker.clone()
  }
}

async fn join_next(
  join_set: &RefCell<task::JoinSet<Result<()>>>,
) -> Option<Result<Result<()>, JoinError>> {
  poll_fn(|cx| join_set.borrow_mut().poll_join_next(cx)).await
}
