//! module: upgrade
//! responsibility: expose a protocol-independent negotiated-stream
//! handle public operations: OnUpgrade::{new,pair},
//! UpgradeTrigger::send data entities: UpgradeFuture, OnUpgrade,
//! UpgradeReceiver, Notification, UpgradeTrigger
//! tests: upgrade_tests.rs

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::sync::oneshot;

use super::Io;

/// Object-safe cloning delegates to the source's own sharing mechanism.
/// The erased handle must not add a second synchronization layer.
trait UpgradeFuture:
  Future<Output = Result<Box<dyn Io>>> + Unpin + Send + Sync
{
  fn clone_box(&self) -> Box<dyn UpgradeFuture>;
}
impl<F> UpgradeFuture for F
where
  F: Future<Output = Result<Box<dyn Io>>>
    + Clone
    + Unpin
    + Send
    + Sync
    + 'static,
{
  fn clone_box(&self) -> Box<dyn UpgradeFuture> {
    Box::new(self.clone())
  }
}

/// Protocol-independent upgrade handle placed in request extensions.
///
/// Clone and poll are delegated to the listener's implementation. HTTP
/// uses Hyper's shared receiver; SOCKS5/H3 use Notification below.
/// There is no shared state or lock in this wrapper.
///
/// Clones share one result, not independent streams. As with Hyper,
/// await only one clone: consuming twice may panic and concurrent
/// waiters may overwrite each other's wakers. These are programming
/// errors, not business failures.
pub(crate) struct OnUpgrade {
  future: Box<dyn UpgradeFuture>,
}

impl Clone for OnUpgrade {
  fn clone(&self) -> Self {
    Self { future: self.future.clone_box() }
  }
}
impl std::fmt::Debug for OnUpgrade {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("OnUpgrade").finish_non_exhaustive()
  }
}
impl OnUpgrade {
  /// Erase a clonable upgrade handle without changing its ownership.
  pub(crate) fn new<F>(future: F) -> Self
  where
    F: Future<Output = Result<Box<dyn Io>>>
      + Clone
      + Unpin
      + Send
      + Sync
      + 'static,
  {
    Self { future: Box::new(future) }
  }

  /// Notification-backed upgrades for listeners that hand over a stream
  /// after sending their protocol response.
  pub(crate) fn pair() -> (UpgradeTrigger, Self) {
    let (sender, receiver) = oneshot::channel();
    (
      UpgradeTrigger { sender },
      Self::new(Notification {
        receiver: Arc::new(Mutex::new(receiver)),
      }),
    )
  }
}
impl Future for OnUpgrade {
  type Output = Result<Box<dyn Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    Pin::new(&mut *self.get_mut().future).poll(cx)
  }
}

type UpgradeReceiver =
  Arc<Mutex<oneshot::Receiver<Result<Box<dyn Io>>>>>;

/// Only notification-backed listeners need this shared receiver.
#[derive(Clone)]
struct Notification {
  receiver: UpgradeReceiver,
}
impl Future for Notification {
  type Output = Result<Box<dyn Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    Pin::new(
      &mut *self.receiver.lock().expect("upgrade receiver poisoned"),
    )
    .poll(cx)
    .map(|result| {
      result
        .unwrap_or_else(|_| Err(anyhow::anyhow!("upgrade canceled")))
    })
  }
}

pub(crate) struct UpgradeTrigger {
  sender: oneshot::Sender<Result<Box<dyn Io>>>,
}
impl UpgradeTrigger {
  pub(crate) fn send(self, result: Result<Box<dyn Io>>) -> Result<()> {
    self.sender.send(result).map_err(|_| {
      anyhow::anyhow!("service dropped the upgrade receiver")
    })
  }
}
