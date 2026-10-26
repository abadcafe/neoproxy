use crate::hostname::{normalize, wildcard_suffix};

#[test]
fn test_normalize_ascii_dns_name_and_root_dot() {
  assert_eq!(normalize("API.Example.COM."), "api.example.com");
  assert_eq!(normalize("[::1]"), "::1");
}

#[test]
fn test_normalize_canonicalizes_ipv6_address_spellings() {
  for input in ["[2001:0db8:0:0::1]", "2001:db8::1"] {
    assert_eq!(normalize(input), "2001:db8::1");
  }
  assert_eq!(wildcard_suffix("::ffff:127.0.0.1"), None);
  assert_eq!(wildcard_suffix("127.0.0.1"), None);
}

#[test]
fn test_wildcard_suffix_requires_one_nonempty_label() {
  assert_eq!(wildcard_suffix("api.example.com"), Some("example.com"));
  assert_eq!(wildcard_suffix(".example.com"), None);
  assert_eq!(wildcard_suffix("example"), None);
}
