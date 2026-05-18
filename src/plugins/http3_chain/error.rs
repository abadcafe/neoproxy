use std::fmt;

// ============================================================================
// Upstream Handle Error Type
// ============================================================================

#[derive(Debug)]
pub(crate) enum UpstreamHandleError {
  DnsError(String),
  ConnectionRefused(String),
  ConnectionTimeout(String),
  DestinationUnavailable(String),
  ProxyInternalResponse(String),
}

impl fmt::Display for UpstreamHandleError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DnsError(msg) => write!(f, "DNS resolution failed: {msg}"),
      Self::ConnectionRefused(msg) => {
        write!(f, "Connection refused: {msg}")
      }
      Self::ConnectionTimeout(msg) => {
        write!(f, "Connection timed out: {msg}")
      }
      Self::DestinationUnavailable(msg) => {
        write!(f, "Destination unavailable: {msg}")
      }
      Self::ProxyInternalResponse(msg) => {
        write!(f, "Proxy internal error: {msg}")
      }
    }
  }
}

impl std::error::Error for UpstreamHandleError {}

/// Classify an anyhow error from `create_quic_connection` into an
/// `UpstreamHandleError` variant by inspecting the error chain.
pub(crate) fn classify_quic_error(e: anyhow::Error) -> UpstreamHandleError {
  // Check for DnsResolveError marker first — it wraps io::Error so
  // this must come before the io::Error downcast.
  if e.downcast_ref::<DnsResolveError>().is_some() {
    return UpstreamHandleError::DnsError(e.to_string());
  }

  // QUIC handshake errors come back as `quinn::ConnectionError`
  // (from awaiting `Connecting`) or `quinn::ConnectError` (from
  // `endpoint.connect()`). These are NOT `std::io::Error`, so they
  // must be checked separately before the io::Error downcast.
  if let Some(conn_err) = e.downcast_ref::<quinn::ConnectionError>() {
    return match conn_err {
      quinn::ConnectionError::TimedOut => {
        UpstreamHandleError::ConnectionTimeout(e.to_string())
      }
      quinn::ConnectionError::ConnectionClosed(_)
      | quinn::ConnectionError::ApplicationClosed(_)
      | quinn::ConnectionError::Reset
      | quinn::ConnectionError::LocallyClosed => {
        UpstreamHandleError::ConnectionRefused(e.to_string())
      }
      _ => UpstreamHandleError::DestinationUnavailable(e.to_string()),
    };
  }

  if let Some(connect_err) = e.downcast_ref::<quinn::ConnectError>() {
    return match connect_err {
      quinn::ConnectError::InvalidServerName(_)
      | quinn::ConnectError::InvalidRemoteAddress(_) => {
        UpstreamHandleError::DnsError(e.to_string())
      }
      _ => UpstreamHandleError::DestinationUnavailable(e.to_string()),
    };
  }

  // Check for io::Error (DNS resolution, socket-level connect failures)
  if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
    return match io_err.kind() {
      std::io::ErrorKind::ConnectionRefused => {
        UpstreamHandleError::ConnectionRefused(e.to_string())
      }
      std::io::ErrorKind::TimedOut => {
        UpstreamHandleError::ConnectionTimeout(e.to_string())
      }
      std::io::ErrorKind::HostUnreachable
      | std::io::ErrorKind::NetworkUnreachable => {
        UpstreamHandleError::DestinationUnavailable(e.to_string())
      }
      std::io::ErrorKind::InvalidInput => {
        // quinn wraps addr parse errors as io::Error with InvalidInput
        UpstreamHandleError::DnsError(e.to_string())
      }
      _ => UpstreamHandleError::DestinationUnavailable(e.to_string()),
    };
  }

  // Default fallback
  UpstreamHandleError::DestinationUnavailable(e.to_string())
}

/// Marker wrapper for DNS resolution errors, so `classify_quic_error`
/// can detect DNS failures via `downcast_ref` instead of guessing from
/// message patterns.
#[derive(Debug)]
pub(crate) struct DnsResolveError(pub(crate) std::io::Error);

impl fmt::Display for DnsResolveError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Display::fmt(&self.0, f)
  }
}

impl std::error::Error for DnsResolveError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_classify_quic_connection_error_timed_out() {
    let err: anyhow::Error = quinn::ConnectionError::TimedOut.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::ConnectionTimeout(_)
    ));
  }

  #[test]
  fn test_classify_quic_connection_error_reset() {
    let err: anyhow::Error = quinn::ConnectionError::Reset.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::ConnectionRefused(_)
    ));
  }

  #[test]
  fn test_classify_quic_connection_error_locally_closed() {
    let err: anyhow::Error = quinn::ConnectionError::LocallyClosed.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::ConnectionRefused(_)
    ));
  }

  #[test]
  fn test_classify_quic_connection_error_version_mismatch() {
    let err: anyhow::Error = quinn::ConnectionError::VersionMismatch.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::DestinationUnavailable(_)
    ));
  }

  #[test]
  fn test_classify_quic_connect_error_invalid_server_name() {
    let err: anyhow::Error =
      quinn::ConnectError::InvalidServerName("bad name".to_string()).into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::DnsError(_)
    ));
  }

  #[test]
  fn test_classify_quic_connect_error_endpoint_stopping() {
    let err: anyhow::Error = quinn::ConnectError::EndpointStopping.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::DestinationUnavailable(_)
    ));
  }

  #[test]
  fn test_classify_dns_resolve_error_takes_precedence() {
    let io_err =
      std::io::Error::new(std::io::ErrorKind::Other, "name lookup failed");
    let err: anyhow::Error = DnsResolveError(io_err).into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::DnsError(_)
    ));
  }

  #[test]
  fn test_classify_io_connection_refused() {
    let io_err = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
    let err: anyhow::Error = io_err.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::ConnectionRefused(_)
    ));
  }

  #[test]
  fn test_classify_io_timed_out() {
    let io_err = std::io::Error::from(std::io::ErrorKind::TimedOut);
    let err: anyhow::Error = io_err.into();
    assert!(matches!(
      classify_quic_error(err),
      UpstreamHandleError::ConnectionTimeout(_)
    ));
  }
}