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

  // Check for io::Error (DNS resolution, connect failures)
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