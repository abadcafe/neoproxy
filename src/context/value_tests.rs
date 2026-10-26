//! Native value serialization through the public context-value
//! interface.
use super::value::ContextValue;

#[test]
fn test_serialize_preserves_numbers_booleans_and_strings() {
  assert_eq!(
    serde_json::to_value(ContextValue::from(42_u64)).unwrap(),
    42
  );
  assert_eq!(
    serde_json::to_value(ContextValue::from(-3_i64)).unwrap(),
    -3
  );
  assert_eq!(
    serde_json::to_value(ContextValue::from(true)).unwrap(),
    true
  );
  assert_eq!(
    serde_json::to_value(ContextValue::from("hello")).unwrap(),
    "hello"
  );
}

#[test]
fn test_serialize_formats_duration_and_addresses_only_at_output() {
  let duration =
    ContextValue::from(std::time::Duration::from_millis(42));
  assert_eq!(serde_json::to_value(&duration).unwrap(), 42);
  assert_eq!(duration.to_string(), "42");
  let address: std::net::SocketAddr = "[::1]:8080".parse().unwrap();
  assert_eq!(
    serde_json::to_value(ContextValue::from(address)).unwrap(),
    "[::1]:8080"
  );
}
