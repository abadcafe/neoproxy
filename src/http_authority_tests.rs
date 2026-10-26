//! Black-box contract for HTTP authority normalization.

use crate::http_authority::{AuthorityError, normalize};

#[test]
fn test_normalize_removes_empty_port_for_dns_ipv4_and_ipv6() {
  for (input, expected) in [
    ("EXAMPLE.com:", "EXAMPLE.com"),
    ("127.0.0.1:", "127.0.0.1"),
    ("[::1]:", "[::1]"),
  ] {
    assert_eq!(
      normalize(&input.parse().unwrap()).unwrap().as_str(),
      expected
    );
  }
}

#[test]
fn test_normalize_preserves_absent_and_explicit_ports() {
  for input in [
    "example.com",
    "example.com:1",
    "example.com:80",
    "example.com:65535",
    "[::1]",
    "[::1]:8080",
  ] {
    assert_eq!(
      normalize(&input.parse().unwrap()).unwrap().as_str(),
      input
    );
  }
}

#[test]
fn test_normalize_rejects_userinfo_and_invalid_nonempty_ports() {
  for input in [
    "user@example.com",
    "user:pass@example.com:80",
    "example.com:abc",
    "example.com:65536",
    "example.com:+80",
  ] {
    assert_eq!(
      normalize(&input.parse().unwrap()),
      Err(AuthorityError::InvalidAuthority),
      "{input}"
    );
  }
}

#[test]
fn test_normalize_rejects_port_zero() {
  for input in ["example.com:0", "[::1]:0"] {
    assert_eq!(
      normalize(&input.parse().unwrap()),
      Err(AuthorityError::PortZero)
    );
  }
}

#[test]
fn test_normalize_rejects_brackets_without_a_valid_ip_literal() {
  for input in ["[]:80", "[example.com]:80", "[:::]:443", "foo[bar]:80"]
  {
    assert_eq!(
      normalize(&input.parse().unwrap()),
      Err(AuthorityError::InvalidAuthority),
      "{input}"
    );
  }
}

#[test]
fn test_normalize_accepts_ipvfuture_and_encoded_ipv6_zone() {
  for input in [
    "[vF.example:future]:80",
    "[fe80::1%25eth0]:80",
    "[::ffff:192.0.2.1]:80",
  ] {
    assert!(normalize(&input.parse().unwrap()).is_ok(), "{input}");
  }
}
