use std::fmt;

/// CONNECT target address parse error
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConnectTargetError {
  NotConnectMethod,
  NoAuthority,
  NoPort,
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
/// - `Ok((host, port))`: Target hostname and port number
/// - `Err(ConnectTargetError)`: Parse failed
pub(crate) fn parse_connect_target(
  parts: &http::request::Parts,
) -> Result<(String, u16), ConnectTargetError> {
  if parts.method != http::Method::CONNECT {
    return Err(ConnectTargetError::NotConnectMethod);
  }

  let authority =
    parts.uri.authority().ok_or(ConnectTargetError::NoAuthority)?;

  let port = authority.port_u16().ok_or(ConnectTargetError::NoPort)?;

  if port == 0 {
    return Err(ConnectTargetError::PortZero);
  }

  Ok((authority.host().to_string(), port))
}

/// Parse forward proxy request target address
///
/// Extracts host, port, and origin-form URI from an absolute-form HTTP
/// request. Only supports http:// scheme (https:// requires CONNECT per RFC).
///
/// # Parameters
/// - `parts`: HTTP request Parts
///
/// # Returns
/// - `Ok((host, port, origin_uri))`: Target hostname, port, and
///   origin-form URI
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
  if authority.as_str().contains('@') {
    return Err(ForwardTargetError::InvalidAuthority);
  }

  let port = authority.port_u16().unwrap_or(80);

  if port == 0 {
    return Err(ForwardTargetError::PortZero);
  }

  Ok(ForwardTarget {
    authority: authority.clone(),
    absolute_uri: uri.clone(),
  })
}

/// Strip hop-by-hop headers from a request/response
///
/// Per RFC 7230, these headers must not be forwarded to the next hop:
/// - connection, keep-alive, proxy-authenticate, proxy-authorization
/// - te, trailers, transfer-encoding, upgrade
/// - Any header names listed in the Connection header value
pub(crate) fn strip_hop_by_hop_headers(headers: &mut http::HeaderMap) {
  // Collect extra names listed in the Connection header value first,
  // before removing Connection itself.
  let connection_tokens: Vec<http::header::HeaderName> = headers
    .get(http::header::CONNECTION)
    .and_then(|v| v.to_str().ok())
    .map(|s| {
      s.split(',').filter_map(|t| t.trim().parse().ok()).collect()
    })
    .unwrap_or_default();

  let hop_by_hop: &[http::header::HeaderName] = &[
    http::header::CONNECTION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::HeaderName::from_static("keep-alive"),
  ];

  for name in hop_by_hop {
    headers.remove(name);
  }
  for name in &connection_tokens {
    headers.remove(name);
  }
}
