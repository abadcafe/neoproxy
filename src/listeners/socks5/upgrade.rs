//! module: upgrade
//! responsibilities: complete SOCKS5 CONNECT negotiation before
//! transferring its stream public operations:
//! Socks5UpgradeTrigger::{pair, send_success, send_error},
//! http_status_to_socks5_error data entities: Socks5UpgradeTrigger
//! tests: SOCKS5 process integration tests
use anyhow::Result;

use crate::stream::{OnUpgrade, UpgradeTrigger};

/// SOCKS5 upgrade trigger (Listener side).
///
/// The listener uses this to send the SOCKS5 reply and resolve
/// the Service's `OnUpgrade` future.
pub(crate) struct Socks5UpgradeTrigger {
  trigger: UpgradeTrigger,
  proto: fast_socks5::server::Socks5ServerProtocol<
    tokio::net::TcpStream,
    fast_socks5::server::states::CommandRead,
  >,
}

impl std::fmt::Debug for Socks5UpgradeTrigger {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Socks5UpgradeTrigger").finish_non_exhaustive()
  }
}

impl Socks5UpgradeTrigger {
  /// Create a linked (trigger, upgrade) pair.
  pub(crate) fn pair(
    proto: fast_socks5::server::Socks5ServerProtocol<
      tokio::net::TcpStream,
      fast_socks5::server::states::CommandRead,
    >,
  ) -> (Self, OnUpgrade) {
    let (trigger, on_upgrade) = OnUpgrade::pair();
    (Self { trigger, proto }, on_upgrade)
  }

  /// Send SOCKS5 success reply and resolve the upgrade future.
  pub(crate) async fn send_success(self) -> Result<()> {
    let proto = self.proto;
    let stream = proto
      .reply_success("0.0.0.0:0".parse()?)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;

    self.trigger.send(Ok(Box::new(stream)))
  }

  /// Send SOCKS5 error reply and resolve the upgrade future with error.
  pub(crate) async fn send_error(
    self,
    error: fast_socks5::ReplyError,
  ) -> Result<()> {
    let proto = self.proto;
    proto
      .reply_error(&error)
      .await
      .map_err(|e| anyhow::anyhow!("SOCKS5 reply failed: {}", e))?;

    self.trigger.send(Err(anyhow::anyhow!("SOCKS5 error: {}", error)))
  }
}

/// Map HTTP status code to SOCKS5 ReplyError.
///
/// Used by the SOCKS5 listener to translate Service response status
/// into appropriate SOCKS5 error codes.
pub(crate) fn http_status_to_socks5_error(
  status: http::StatusCode,
) -> fast_socks5::ReplyError {
  match status {
    http::StatusCode::BAD_GATEWAY => {
      fast_socks5::ReplyError::ConnectionRefused
    }
    http::StatusCode::SERVICE_UNAVAILABLE => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    http::StatusCode::GATEWAY_TIMEOUT => {
      fast_socks5::ReplyError::ConnectionTimeout
    }
    http::StatusCode::FORBIDDEN => {
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    http::StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
      // Request-level policy can still deny an authenticated
      // connection.
      fast_socks5::ReplyError::ConnectionNotAllowed
    }
    _ => fast_socks5::ReplyError::GeneralFailure,
  }
}

// ============================================================================
// Tunnel functions
// ============================================================================
