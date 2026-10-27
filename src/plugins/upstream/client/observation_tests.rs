//! Connection metadata is copied into request contexts without
//! retaining them.
use std::sync::Arc;
use std::time::Duration;

use super::observation::ConnectionObservation;
use crate::context::RequestContext;
use crate::context::fields::{connection, dns};

#[test]
fn test_same_connection_preserves_identity_across_clones_only() {
  let first = ConnectionObservation::new();
  let cloned = first.clone();
  let other = ConnectionObservation::new();
  assert!(first.same_connection(&cloned));
  assert!(cloned.same_connection(&first));
  assert!(!first.same_connection(&other));
}

#[test]
fn test_record_attributes_setup_once_and_reused_connections_without_setup_times()
 {
  let observation = ConnectionObservation::new();
  observation.dns(
    "localhost",
    Duration::from_millis(2),
    Duration::from_secs(1),
    &["127.0.0.1:0".parse().unwrap()],
  );
  observation.tcp(
    Some("127.0.0.1:80".parse().unwrap()),
    Some("127.0.0.1:30000".parse().unwrap()),
    Duration::from_millis(3),
  );
  observation.tls(Duration::from_millis(5));
  let first = RequestContext::new();
  observation.record(&first);
  assert_eq!(first.get(connection::REUSED), Some(false));
  assert_eq!(first.get(dns::HOST).as_deref(), Some("localhost"));
  assert_eq!(first.get(dns::TIME), Some(Duration::from_millis(2)));
  assert_eq!(
    first.get(connection::TLS_TIME),
    Some(Duration::from_millis(5))
  );
  let second = RequestContext::new();
  observation.record(&second);
  assert_eq!(second.get(connection::REUSED), Some(true));
  assert_eq!(second.get(connection::PEER), first.get(connection::PEER));
  assert!(second.get(dns::TIME).is_none());
  assert!(second.get(connection::TLS_TIME).is_none());
  assert_eq!(first.get(connection::REUSED), Some(false));
  let addresses: Arc<[std::net::IpAddr]> =
    first.get(dns::ADDRESSES).unwrap();
  assert_eq!(
    addresses.as_ref(),
    &["127.0.0.1".parse::<std::net::IpAddr>().unwrap()]
  );
}

#[test]
fn test_record_error_preserves_observations_and_original_error_kind() {
  let observation = ConnectionObservation::new();
  observation.dns(
    "unreachable.test",
    Duration::from_millis(10),
    Duration::from_millis(10),
    &[],
  );
  let error = observation.error(std::io::Error::new(
    std::io::ErrorKind::TimedOut,
    "DNS deadline",
  ));
  let context = RequestContext::new();
  ConnectionObservation::record_error(&error, &context);
  assert_eq!(
    context.get(dns::HOST).as_deref(),
    Some("unreachable.test")
  );
  assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
  assert!(error.to_string().contains("DNS deadline"));
}
