//! Public request identity and header propagation contracts.
use std::collections::HashSet;

use crate::request_id::RequestId;

#[test]
fn test_read_or_generate_preserves_opaque_incoming_value_and_headers() {
  let mut headers = http::HeaderMap::new();
  headers
    .insert("x-request-id", "client-value-not-a-uuid".parse().unwrap());
  let original = headers.clone();
  let id = RequestId::read_or_generate(&headers).unwrap();
  let mut outgoing = http::HeaderMap::new();
  outgoing.append("x-request-id", "other".parse().unwrap());
  outgoing.append("x-request-id", "duplicate".parse().unwrap());
  id.apply(&mut outgoing);
  assert_eq!(headers, original);
  assert_eq!(outgoing["x-request-id"], "client-value-not-a-uuid");
  assert_eq!(outgoing.get_all("x-request-id").iter().count(), 1);
}

#[test]
fn test_read_or_generate_missing_header_creates_distinct_hex_ids_without_mutating_input()
 {
  let headers = http::HeaderMap::new();
  let mut ids = HashSet::new();
  for _ in 0..1000 {
    let id = RequestId::read_or_generate(&headers).unwrap();
    let text = id.to_string();
    assert_eq!(text.len(), 32);
    assert!(text.bytes().all(
      |byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
    ));
    assert!(ids.insert(text));
  }
  assert!(headers.is_empty());
}

#[test]
fn test_read_or_generate_is_independent_across_worker_threads() {
  let workers: Vec<_> = (0..8)
    .map(|_| {
      std::thread::spawn(|| {
        (0..100)
          .map(|_| {
            RequestId::read_or_generate(&http::HeaderMap::new())
              .unwrap()
              .to_string()
          })
          .collect::<Vec<_>>()
      })
    })
    .collect();
  let ids: Vec<_> = workers
    .into_iter()
    .flat_map(|worker| worker.join().unwrap())
    .collect();
  assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
}
