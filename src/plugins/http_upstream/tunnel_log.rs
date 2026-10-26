//! module: tunnel_log
//! responsibility: emit exactly one terminal tunnel business event
//! public operations: TunnelLog::{new,progress,finish,upgrade_failed}
//! data entities: TunnelLog, EndReason
//! tests: tunnel_log_tests.rs and request-context process tests
use std::net::SocketAddr;
use std::time::Instant;

use crate::context::RequestContext;
use crate::request_id::RequestId;
use crate::stream::{IoSide, TransferEnd, TransferProgress};

pub(super) struct TunnelLog {
  id: RequestId,
  client: Option<SocketAddr>,
  target: String,
  upstream: Option<SocketAddr>,
  started: Instant,
  progress: TransferProgress,
  finished: bool,
}
#[derive(Clone, Copy)]
enum EndReason {
  Completed,
  IdleTimeout,
  Shutdown,
  IoError,
  UpgradeFailed,
  Cancelled,
}
impl std::fmt::Display for EndReason {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::Completed => "completed",
      Self::IdleTimeout => "idle_timeout",
      Self::Shutdown => "shutdown",
      Self::IoError => "io_error",
      Self::UpgradeFailed => "upgrade_failed",
      Self::Cancelled => "cancelled",
    })
  }
}
impl TunnelLog {
  pub(super) fn new(
    ctx: &RequestContext,
    target: &str,
    upstream: Option<SocketAddr>,
  ) -> Self {
    Self {
      id: ctx
        .request_id()
        .expect("tunnel must have a creating request ID")
        .clone(),
      client: ctx.client_addr(),
      target: target.into(),
      upstream,
      started: Instant::now(),
      progress: TransferProgress::new(),
      finished: false,
    }
  }

  pub(super) fn progress(&self) -> TransferProgress {
    self.progress.clone()
  }

  pub(super) fn finish(mut self, end: TransferEnd) {
    match end {
      TransferEnd::Completed => {
        self.emit(EndReason::Completed, None, None, "")
      }
      TransferEnd::IdleTimeout => {
        self.emit(EndReason::IdleTimeout, None, None, "")
      }
      TransferEnd::Shutdown => {
        self.emit(EndReason::Shutdown, None, None, "")
      }
      TransferEnd::Failed { side, error } => self.emit(
        EndReason::IoError,
        side,
        Some(error.kind()),
        &error.to_string(),
      ),
    }
  }

  pub(super) fn upgrade_failed(
    mut self,
    error: &dyn std::fmt::Display,
  ) {
    self.emit(EndReason::UpgradeFailed, None, None, &error.to_string());
  }

  fn emit(
    &mut self,
    reason: EndReason,
    side: Option<IoSide>,
    kind: Option<std::io::ErrorKind>,
    error: &str,
  ) {
    assert!(!self.finished, "terminal tunnel event emitted twice");
    self.finished = true;
    let totals: crate::stream::TransferTotals = self.progress.totals();
    let duration_ms = self.started.elapsed().as_millis();
    let client = self
      .client
      .map(|address| address.to_string())
      .unwrap_or_default();
    let upstream = self
      .upstream
      .map(|address| address.to_string())
      .unwrap_or_default();
    let side = side.map(|side| side.to_string()).unwrap_or_default();
    let kind = kind.map(|kind| format!("{kind:?}")).unwrap_or_default();
    macro_rules! terminal { ($level:ident) => {
      tracing::$level!(request_id = %self.id, client_addr = %client, target = %self.target, upstream_addr = %upstream, duration_ms, bytes_client_to_upstream = totals.client_to_upstream, bytes_upstream_to_client = totals.upstream_to_client, end_reason = %reason, error_side = %side, error_kind = %kind, error, "tunnel_finished");
    }; }
    match reason {
      EndReason::IdleTimeout
      | EndReason::IoError
      | EndReason::UpgradeFailed => {
        terminal!(warn);
      }
      EndReason::Completed
      | EndReason::Shutdown
      | EndReason::Cancelled => {
        terminal!(info);
      }
    }
  }
}
impl Drop for TunnelLog {
  fn drop(&mut self) {
    if !self.finished {
      self.emit(EndReason::Cancelled, None, None, "");
    }
  }
}
