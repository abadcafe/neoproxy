//! Black-box contracts for the protocol information at each hop.
use crate::via::append;

#[test]
fn test_append_preserves_previous_hops_and_received_protocol_version() {
  for (version, expected) in [
    (http::Version::HTTP_10, "1.0 neoproxy"),
    (http::Version::HTTP_11, "1.1 neoproxy"),
    (http::Version::HTTP_3, "3 neoproxy"),
  ] {
    let mut headers = http::HeaderMap::new();
    headers.append("via", "1.0 first".parse().unwrap());
    append(&mut headers, version);
    let entries: Vec<_> = headers.get_all("via").iter().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0], "1.0 first");
    assert_eq!(entries[1], expected);
  }
}
