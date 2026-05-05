//! Shared tunnel logic for bidirectional data transfer.
//!
//! Extracted from `connect_tcp` and `http3_chain` to avoid code
//! duplication.

use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{error, info, warn};

use crate::shutdown::ShutdownHandle;
use crate::stream::{ClientStream, H3OnUpgrade, Socks5OnUpgrade};

/// Default idle timeout for tunnel data transfer (60 seconds).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;

/// Resolve upgrade futures into a `ClientStream`.
///
/// Attempts SOCKS5, then H3, then HTTP upgrade in order.
/// Returns `Err` with a description if none succeed.
pub async fn resolve_client_stream(
  socks5_upgrade: Option<Socks5OnUpgrade>,
  h3_upgrade: Option<H3OnUpgrade>,
  http_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<ClientStream, String> {
  if let Some(socks5) = socks5_upgrade {
    match socks5.await {
      Ok(stream) => Ok(ClientStream::Socks5(stream)),
      Err(e) => Err(format!("SOCKS5 upgrade failed: {e}")),
    }
  } else if let Some(h3) = h3_upgrade {
    match h3.await {
      Ok(stream) => Ok(ClientStream::H3(stream)),
      Err(e) => Err(format!("H3 upgrade failed: {e}")),
    }
  } else if let Some(http) = http_upgrade {
    match http.await {
      Ok(upgraded) => Ok(ClientStream::Http(TokioIo::new(upgraded))),
      Err(e) => Err(format!("HTTP upgrade failed: {e}")),
    }
  } else {
    Err("no upgrade available".to_string())
  }
}

/// Run bidirectional copy between client and target streams.
///
/// Handles shutdown notification and idle timeout. Logs the outcome.
pub async fn run_tunnel<T>(
  client: &mut ClientStream,
  target: &mut T,
  shutdown_handle: ShutdownHandle,
  idle_timeout: Duration,
  addr: &str,
) where
  T: AsyncRead + AsyncWrite + Unpin,
{
  if shutdown_handle.is_shutdown() {
    warn!("tunnel to {addr}: shutdown already triggered, aborting");
    return;
  }

  info!("tunnel to {addr}: starting bidirectional transfer");

  let result = tokio::select! {
    res = tokio::time::timeout(
      idle_timeout,
      tokio::io::copy_bidirectional(client, target),
    ) => res,
    _ = shutdown_handle.notified() => {
      warn!("tunnel to {addr}: shutdown by notification");
      return;
    }
  };

  match result {
    Ok(Ok((_sent, _received))) => {
      info!("tunnel to {addr}: transfer completed");
    }
    Ok(Err(e)) => {
      error!("tunnel to {addr}: transfer error: {e}");
    }
    Err(_) => {
      warn!(
        "tunnel to {addr}: idle timeout after {idle_timeout:?}, \
         closing"
      );
    }
  }
}
