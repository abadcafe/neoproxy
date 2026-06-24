use std::fmt;

use crate::context::RequestContext;
use crate::http_message::{
  Response, build_empty_response, build_proxy_status_error,
  build_proxy_status_with_status,
};

// ============================================================================
// Upstream Error Type (RFC 9209 Proxy-Status error types)
// ============================================================================

#[derive(Debug)]
pub(crate) enum UpstreamError {
  DnsError(String),
  ConnectionRefused(String),
  ConnectionTimeout(String),
  ConnectionTerminated(String),
  TlsCertificateError(String),
  TlsProtocolError(String),
  DestinationUnavailable(String),
  ProxyInternalError(String),
  /// Upstream proxy returned a non-2xx CONNECT response.
  /// The status and proxy-status should be relayed to the downstream
  /// client.
  UpstreamConnectError {
    status: http::StatusCode,
    upstream_proxy_status: Option<http::HeaderValue>,
  },
}

impl UpstreamError {
  pub(crate) fn http_status(&self) -> http::StatusCode {
    match self {
      Self::DnsError(_)
      | Self::ConnectionRefused(_)
      | Self::ConnectionTerminated(_)
      | Self::TlsCertificateError(_)
      | Self::TlsProtocolError(_)
      | Self::DestinationUnavailable(_) => {
        http::StatusCode::BAD_GATEWAY
      }
      Self::ConnectionTimeout(_) => http::StatusCode::GATEWAY_TIMEOUT,
      Self::ProxyInternalError(_) => {
        http::StatusCode::SERVICE_UNAVAILABLE
      }
      Self::UpstreamConnectError { status, .. } => {
        // Relay upstream status; 407 becomes 502 per HTTP proxy
        // conventions
        if *status == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
          http::StatusCode::BAD_GATEWAY
        } else {
          *status
        }
      }
    }
  }

  pub(crate) fn proxy_status_error(&self) -> &'static str {
    match self {
      Self::DnsError(_) => "dns_error",
      Self::ConnectionRefused(_) => "connection_refused",
      Self::ConnectionTimeout(_) => "connection_timeout",
      Self::ConnectionTerminated(_) => "connection_terminated",
      Self::TlsCertificateError(_) => "tls_certificate_error",
      Self::TlsProtocolError(_) => "tls_protocol_error",
      Self::DestinationUnavailable(_) => "destination_unavailable",
      Self::ProxyInternalError(_) => "proxy_internal_error",
      Self::UpstreamConnectError { .. } => "upstream_error",
    }
  }

  pub(crate) fn to_response(&self, ctx: &RequestContext) -> Response {
    let status = self.http_status();
    let mut resp = build_empty_response(status);
    let id =
      ctx.get("proxy_id").unwrap_or_else(|| "neoproxy".to_string());

    if let Self::UpstreamConnectError {
      status,
      upstream_proxy_status,
    } = self
    {
      // Append our proxy-status entry to the upstream's
      let our_entry =
        build_proxy_status_with_status(&id, status.as_u16());
      resp.headers_mut().insert(
        http::header::HeaderName::from_static("proxy-status"),
        crate::http_message::append_proxy_status(
          upstream_proxy_status.as_ref(),
          &our_entry,
        ),
      );
    } else {
      let our_entry =
        build_proxy_status_error(&id, self.proxy_status_error());
      resp.headers_mut().insert(
        http::header::HeaderName::from_static("proxy-status"),
        our_entry,
      );
    }
    resp
  }
}

impl fmt::Display for UpstreamError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DnsError(msg) => write!(f, "DNS resolution failed: {msg}"),
      Self::ConnectionRefused(msg) => {
        write!(f, "Connection refused: {msg}")
      }
      Self::ConnectionTimeout(msg) => {
        write!(f, "Connection timed out: {msg}")
      }
      Self::ConnectionTerminated(msg) => {
        write!(f, "Connection terminated: {msg}")
      }
      Self::TlsCertificateError(msg) => {
        write!(f, "TLS certificate error: {msg}")
      }
      Self::TlsProtocolError(msg) => {
        write!(f, "TLS protocol error: {msg}")
      }
      Self::DestinationUnavailable(msg) => {
        write!(f, "Destination unavailable: {msg}")
      }
      Self::ProxyInternalError(msg) => {
        write!(f, "Proxy internal error: {msg}")
      }
      Self::UpstreamConnectError { status, .. } => {
        write!(f, "Upstream CONNECT error: {status}")
      }
    }
  }
}

impl std::error::Error for UpstreamError {}

// ============================================================================
// DNS Resolve Error Marker
// ============================================================================

/// Marker wrapper for DNS resolution errors, so classifiers can detect
/// DNS failures via `downcast_ref` instead of guessing from message
/// patterns.
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

// ============================================================================
// Error Classifiers
// ============================================================================

/// Classify an anyhow error from TCP connect into an `UpstreamError`.
pub(crate) fn classify_connect_error(
  e: anyhow::Error,
) -> UpstreamError {
  if e.downcast_ref::<DnsResolveError>().is_some() {
    return UpstreamError::DnsError(e.to_string());
  }

  if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
    return match io_err.kind() {
      std::io::ErrorKind::ConnectionRefused => {
        UpstreamError::ConnectionRefused(e.to_string())
      }
      std::io::ErrorKind::TimedOut => {
        UpstreamError::ConnectionTimeout(e.to_string())
      }
      std::io::ErrorKind::ConnectionReset => {
        UpstreamError::ConnectionTerminated(e.to_string())
      }
      std::io::ErrorKind::HostUnreachable
      | std::io::ErrorKind::NetworkUnreachable
      | std::io::ErrorKind::AddrNotAvailable => {
        UpstreamError::DestinationUnavailable(e.to_string())
      }
      _ => UpstreamError::ProxyInternalError(e.to_string()),
    };
  }

  UpstreamError::ProxyInternalError(e.to_string())
}

/// Classify an anyhow error from QUIC connection establishment into an
/// `UpstreamError`. With RFC 9209
/// variants: ConnectionReset → ConnectionTerminated (not
/// ConnectionRefused), plus TLS error classification.
pub(crate) fn classify_quic_error(e: anyhow::Error) -> UpstreamError {
  if e.downcast_ref::<DnsResolveError>().is_some() {
    return UpstreamError::DnsError(e.to_string());
  }

  if let Some(conn_err) = e.downcast_ref::<quinn::ConnectionError>() {
    return match conn_err {
      quinn::ConnectionError::TimedOut => {
        UpstreamError::ConnectionTimeout(e.to_string())
      }
      quinn::ConnectionError::ConnectionClosed(_)
      | quinn::ConnectionError::ApplicationClosed(_)
      | quinn::ConnectionError::Reset
      | quinn::ConnectionError::LocallyClosed => {
        UpstreamError::ConnectionTerminated(e.to_string())
      }
      _ => UpstreamError::DestinationUnavailable(e.to_string()),
    };
  }

  if let Some(connect_err) = e.downcast_ref::<quinn::ConnectError>() {
    return match connect_err {
      quinn::ConnectError::InvalidServerName(_)
      | quinn::ConnectError::InvalidRemoteAddress(_) => {
        UpstreamError::DnsError(e.to_string())
      }
      _ => UpstreamError::DestinationUnavailable(e.to_string()),
    };
  }

  if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
    return match io_err.kind() {
      std::io::ErrorKind::ConnectionRefused => {
        UpstreamError::ConnectionRefused(e.to_string())
      }
      std::io::ErrorKind::TimedOut => {
        UpstreamError::ConnectionTimeout(e.to_string())
      }
      std::io::ErrorKind::HostUnreachable
      | std::io::ErrorKind::NetworkUnreachable => {
        UpstreamError::DestinationUnavailable(e.to_string())
      }
      std::io::ErrorKind::InvalidInput => {
        UpstreamError::DnsError(e.to_string())
      }
      _ => UpstreamError::DestinationUnavailable(e.to_string()),
    };
  }

  UpstreamError::DestinationUnavailable(e.to_string())
}

/// Classify an anyhow error from TLS handshake (tokio-rustls) into an
/// `UpstreamError`. Distinguishes certificate errors from protocol
/// errors by inspecting `rustls::Error` variants.
pub(crate) fn classify_tls_handshake_error(
  e: anyhow::Error,
) -> UpstreamError {
  if let Some(tls_err) = e.downcast_ref::<rustls::Error>() {
    return match tls_err {
      rustls::Error::InvalidCertificate(_)
      | rustls::Error::NoCertificatesPresented
      | rustls::Error::InvalidCertRevocationList(_) => {
        UpstreamError::TlsCertificateError(e.to_string())
      }
      _ => UpstreamError::TlsProtocolError(e.to_string()),
    };
  }

  UpstreamError::TlsProtocolError(e.to_string())
}
