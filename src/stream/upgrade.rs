//! module: upgrade
//! responsibilities: transfer negotiated protocol streams to request
//! handlers public operations: OnUpgrade, UpgradeTrigger,
//! extract_upgrade data entities: UpgradeReceiver,
//! UpgradeFuture, OnUpgrade, UpgradeTrigger
//! tests: upgrade_tests.rs

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::Result;
use hyper_util::rt::TokioIo;
use tokio::sync::oneshot;

use super::Io;
use crate::http_message::RequestBody;

type UpgradeReceiver =
  Arc<Mutex<oneshot::Receiver<Result<Box<dyn Io>>>>>;
pub(crate) type UpgradeFuture =
  Pin<Box<dyn Future<Output = Result<Box<dyn Io>>>>>;

// ============================================================================
// OnUpgrade - unified upgrade future
// ============================================================================

/// Unified upgrade future for SOCKS5 and H3 listeners.
///
/// Placed into `Request.extensions` by the listener.
/// Service extracts it via `OnUpgrade::on()` and awaits to receive
/// the upgraded stream after the listener sends the protocol response.
///
/// Mirrors `hyper::upgrade::OnUpgrade`: clones share one receiver.
/// `Clone` is required by `http::Extensions`; it does not provide
/// independent upgrade results. Await only one clone, and never consume
/// the result twice.
///
/// # Panics
/// Polling a clone after the shared receiver has completed can panic
/// inside Tokio. Concurrent waiters can also overwrite each other's
/// wakers and remain pending. These are programming errors:
/// intentionally preserve Hyper's behavior rather than disguise misuse
/// as a business error or add a second consumer protocol.
#[derive(Clone)]
pub(crate) struct OnUpgrade {
  rx: Option<UpgradeReceiver>,
}

impl std::fmt::Debug for OnUpgrade {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("OnUpgrade").finish_non_exhaustive()
  }
}

impl OnUpgrade {
  /// Extract `OnUpgrade` from Request extensions.
  ///
  /// Returns `None` if no upgrade is available.
  pub(crate) fn on(
    req: &mut http::Request<RequestBody>,
  ) -> Option<Self> {
    req.extensions_mut().remove::<Self>()
  }

  /// Create a linked (trigger, on_upgrade) pair.
  pub(crate) fn pair() -> (UpgradeTrigger, Self) {
    let (tx, rx) = oneshot::channel();
    (
      UpgradeTrigger { sender: tx },
      Self { rx: Some(Arc::new(Mutex::new(rx))) },
    )
  }
}

impl Future for OnUpgrade {
  type Output = Result<Box<dyn Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Self::Output> {
    match &self.rx {
      Some(rx) => {
        // Match Hyper: polling a consumed shared receiver is programmer
        // misuse. Let Tokio panic instead of returning a business
        // error.
        Pin::new(&mut *rx.lock().unwrap()).poll(cx).map(|result| {
          result.unwrap_or_else(|_| {
            Err(anyhow::anyhow!("upgrade canceled"))
          })
        })
      }
      None => Poll::Ready(Err(anyhow::anyhow!("no upgrade available"))),
    }
  }
}

// ============================================================================
// UpgradeTrigger - generic trigger for listeners
// ============================================================================

/// Trigger for listeners to complete the upgrade.
///
/// Used internally by `H3UpgradeTrigger` and `Socks5UpgradeTrigger`.
pub(crate) struct UpgradeTrigger {
  sender: oneshot::Sender<Result<Box<dyn Io>>>,
}

impl UpgradeTrigger {
  /// Send the upgraded stream to the service.
  pub(crate) fn send(self, result: Result<Box<dyn Io>>) -> Result<()> {
    self.sender.send(result).map_err(|_| {
      anyhow::anyhow!("service dropped the upgrade receiver")
    })
  }
}

// ============================================================================
// Upgrade extraction
// ============================================================================

/// Extract an upgrade future from the request.
///
/// Prefers our custom `OnUpgrade` (SOCKS5/H3), falls back to hyper's
/// HTTP upgrade. Returns `None` if no upgrade is available.
pub(crate) fn extract_upgrade(
  req: &mut http::Request<crate::http_message::RequestBody>,
) -> Option<UpgradeFuture> {
  if let Some(u) = OnUpgrade::on(req) {
    return Some(Box::pin(u));
  }
  match req.extensions().get::<hyper::upgrade::OnUpgrade>() {
    Some(_) => {
      let http_upgrade = hyper::upgrade::on(req);
      Some(Box::pin(async move {
        let upgraded = http_upgrade.await?;
        Ok(Box::new(TokioIo::new(upgraded)) as Box<dyn Io>)
      }))
    }
    None => None,
  }
}
