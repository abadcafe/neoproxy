//! module: target_parser
//! responsibilities: validate upstream request targets
//! public operations: parse_connect_target, parse_forward_target,
//! ConnectTarget::{authority, uri},
//! ForwardTarget::{absolute_uri, host_header_value}
//! data entities: ConnectTargetError, ForwardTargetError,
//! ConnectTarget, ForwardTarget
//! tests: target_parser_tests.rs

use std::fmt;

use crate::http_authority::{self, AuthorityError};

/// CONNECT target address parse error
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectTargetError {
  NotConnectMethod,
  NoAuthority,
  NoPort,
  InvalidAuthority,
  PortZero,
}

/// Forward proxy target address parse error
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ForwardTargetError {
  ConnectMethod,
  NotAbsoluteForm,
  UnsupportedScheme,
  NoAuthority,
  InvalidAuthority,
  PortZero,
}

/// A validated CONNECT authority with an explicit nonzero u16 port.
/// Only parse_connect_target can construct this value; transports
/// cannot substitute an unchecked string after request validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectTarget {
  authority: http::uri::Authority,
}

impl ConnectTarget {
  pub(crate) fn authority(&self) -> &str {
    self.authority.as_str()
  }

  pub(crate) fn uri(&self) -> http::Uri {
    // A validated Authority always forms an authority-only URI.
    // Failure means this module broke its invariant, so intentionally
    // panic rather than disguise a programming error as an HTTP error.
    http::Uri::builder()
      .authority(self.authority.clone())
      .build()
      .expect("validated CONNECT authority must form a URI")
  }
}

impl fmt::Display for ConnectTarget {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.authority())
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardTarget {
  authority: http::uri::Authority,
  absolute_uri: http::Uri,
}

impl ForwardTarget {
  pub(crate) fn absolute_uri(&self) -> &http::Uri {
    &self.absolute_uri
  }

  pub(crate) fn host_header_value(
    &self,
  ) -> Result<http::HeaderValue, ForwardTargetError> {
    http::HeaderValue::from_str(self.authority.as_str())
      .map_err(|_| ForwardTargetError::InvalidAuthority)
  }
}

impl fmt::Display for ConnectTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ConnectTargetError::NotConnectMethod => {
        write!(f, "not CONNECT method")
      }
      ConnectTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ConnectTargetError::InvalidAuthority => {
        write!(f, "invalid CONNECT authority")
      }
      ConnectTargetError::NoPort => {
        write!(f, "no port in authority")
      }
      ConnectTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ConnectTargetError {}

impl fmt::Display for ForwardTargetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      ForwardTargetError::ConnectMethod => {
        write!(f, "CONNECT method not allowed for forward proxy")
      }
      ForwardTargetError::NotAbsoluteForm => {
        write!(f, "URI must be absolute-form (http://host/path)")
      }
      ForwardTargetError::UnsupportedScheme => {
        write!(f, "only http:// scheme supported for forward proxy")
      }
      ForwardTargetError::NoAuthority => {
        write!(f, "no authority in URI")
      }
      ForwardTargetError::InvalidAuthority => {
        write!(f, "invalid authority in URI")
      }
      ForwardTargetError::PortZero => {
        write!(f, "port is zero")
      }
    }
  }
}

impl std::error::Error for ForwardTargetError {}

/// Parse CONNECT request target address
///
/// # Parameters
/// - `parts`: HTTP request Parts
///
/// # Returns
/// - `Ok(ConnectTarget)`: Validated authority for transport operations
/// - `Err(ConnectTargetError)`: Parse failed
pub(crate) fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<ConnectTarget, ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  if parts.version != http::Version::HTTP_3
    && (parts.uri.scheme().is_some()
      || parts.uri.path_and_query().is_some())
  {
    return Err(ConnectTargetError::InvalidAuthority);
  }
  let authority = http_authority::normalize(authority).map_err(
    |error| match error {
      AuthorityError::InvalidAuthority => {
        ConnectTargetError::InvalidAuthority
      }
      AuthorityError::PortZero => ConnectTargetError::PortZero,
    },
  )?;
  authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  Ok(ConnectTarget { authority })
}

/// Parse forward proxy request target address
///
/// Validate an absolute-form request and normalize its authority.
/// This service supports http:// forwarding; HTTPS targets use CONNECT.
///
/// # Parameters
/// - `parts`: HTTP request Parts
///
/// # Returns
/// - `Ok(ForwardTarget)`: Normalized absolute URI and Host field source
/// - `Err(ForwardTargetError)`: Parse failed
pub(crate) fn parse_forward_target(
  parts: &http::request::Parts,
) -> Result<ForwardTarget, ForwardTargetError> {
  if parts.method == http::Method::CONNECT {
    return Err(ForwardTargetError::ConnectMethod);
  }

  let uri = &parts.uri;

  let scheme =
    uri.scheme().ok_or(ForwardTargetError::NotAbsoluteForm)?;
  if scheme != &http::uri::Scheme::HTTP {
    return Err(ForwardTargetError::UnsupportedScheme);
  }

  let authority =
    uri.authority().ok_or(ForwardTargetError::NoAuthority)?;
  let authority = http_authority::normalize(authority).map_err(
    |error| match error {
      AuthorityError::InvalidAuthority => {
        ForwardTargetError::InvalidAuthority
      }
      AuthorityError::PortZero => ForwardTargetError::PortZero,
    },
  )?;
  let mut uri_parts = uri.clone().into_parts();
  uri_parts.authority = Some(authority.clone());
  let absolute_uri = http::Uri::from_parts(uri_parts)
    .map_err(|_| ForwardTargetError::InvalidAuthority)?;

  Ok(ForwardTarget { authority, absolute_uri })
}
