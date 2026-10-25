//! module: http_authority
//! responsibilities: validate and normalize HTTP host/port authorities
//! public operations: normalize
//! data entities: AuthorityError
//! tests: http_authority_tests.rs

use http::uri::Authority;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityError {
  InvalidAuthority,
  PortZero,
}

/// RFC 9110 §4.2.1–4.2.3: an absent or empty port uses the scheme's
/// default. Remove the empty separator for forwarding, preserving the
/// host (including IPv6 brackets) and any nonempty valid port.
/// Reject userinfo, nondecimal ports, zero and values above 65535.
/// CONNECT callers additionally require an explicit port.
pub(crate) fn normalize(
  authority: &Authority,
) -> Result<Authority, AuthorityError> {
  let host = authority.host();
  if host.is_empty() || authority.as_str().contains('@') {
    return Err(AuthorityError::InvalidAuthority);
  }
  let suffix = authority
    .as_str()
    .strip_prefix(host)
    .ok_or(AuthorityError::InvalidAuthority)?;
  match suffix {
    "" => Ok(authority.clone()),
    ":" => host.parse().map_err(|_| AuthorityError::InvalidAuthority),
    _ => {
      let port = suffix
        .strip_prefix(':')
        .filter(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|port| port.parse::<u16>().ok())
        .ok_or(AuthorityError::InvalidAuthority)?;
      if port == 0 {
        return Err(AuthorityError::PortZero);
      }
      Ok(authority.clone())
    }
  }
}
