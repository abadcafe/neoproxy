//! module: transfer
//! responsibility: retain tunnel progress independently of a transfer
//! future's lifetime public operations: TransferProgress::{new,totals},
//! TransferTotals, TransferEnd, IoSide data entities: TransferProgress,
//! TransferTotals, TransferEnd, IoSide, WrittenCounter
//! tests: stream_transfer_tests.rs through stream's public interface
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub(crate) struct TransferProgress {
  client: WrittenCounter,
  upstream: WrittenCounter,
}
#[derive(Clone)]
pub(super) struct WrittenCounter(Arc<AtomicU64>);
impl WrittenCounter {
  pub(super) fn add(&self, count: usize) {
    self.0.fetch_add(count as u64, Ordering::Relaxed);
  }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransferTotals {
  pub(crate) client_to_upstream: u64,
  pub(crate) upstream_to_client: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IoSide {
  Client,
  Upstream,
}
impl std::fmt::Display for IoSide {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::Client => "client",
      Self::Upstream => "upstream",
    })
  }
}
#[derive(Debug)]
pub(crate) enum TransferEnd {
  Completed,
  IdleTimeout,
  Shutdown,
  Failed { side: Option<IoSide>, error: std::io::Error },
}
impl TransferProgress {
  pub(crate) fn new() -> Self {
    Self {
      client: WrittenCounter(Arc::new(AtomicU64::new(0))),
      upstream: WrittenCounter(Arc::new(AtomicU64::new(0))),
    }
  }

  pub(crate) fn totals(&self) -> TransferTotals {
    TransferTotals {
      client_to_upstream: self.upstream.0.load(Ordering::Relaxed),
      upstream_to_client: self.client.0.load(Ordering::Relaxed),
    }
  }

  pub(super) fn client_written(&self) -> WrittenCounter {
    self.client.clone()
  }

  pub(super) fn upstream_written(&self) -> WrittenCounter {
    self.upstream.clone()
  }
}
