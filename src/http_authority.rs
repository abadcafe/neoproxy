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
  if host.is_empty()
    || !valid_literal(host)
    || authority.as_str().contains('@')
  {
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

// http::Authority checks delimiters and URI bytes, but deliberately
// does not validate the address inside brackets. Keep that protocol
// validation at our shared ingress/egress boundary.
fn valid_literal(host: &str) -> bool {
  if !host.contains(['[', ']']) {
    return true;
  }
  let Some(literal) =
    host.strip_prefix('[').and_then(|host| host.strip_suffix(']'))
  else {
    return false;
  };
  if let Some(future) = literal.strip_prefix(['v', 'V']) {
    let Some((version, address)) = future.split_once('.') else {
      return false;
    };
    return !version.is_empty()
      && version.bytes().all(|byte| byte.is_ascii_hexdigit())
      && !address.is_empty()
      && address.bytes().all(|byte| {
        unreserved(byte) || b"!$&'()*+,;=:".contains(&byte)
      });
  }
  let (address, zone) = literal
    .split_once("%25")
    .map_or((literal, None), |(address, zone)| (address, Some(zone)));
  address.parse::<std::net::Ipv6Addr>().is_ok()
    && zone.is_none_or(valid_zone)
}

fn unreserved(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}

fn valid_zone(zone: &str) -> bool {
  if zone.is_empty() {
    return false;
  }
  let mut bytes = zone.bytes();
  while let Some(byte) = bytes.next() {
    if unreserved(byte) {
      continue;
    }
    if byte != b'%'
      || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
      || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
    {
      return false;
    }
  }
  true
}
