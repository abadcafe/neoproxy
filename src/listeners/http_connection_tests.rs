use super::http_connection::HeaderDeadline;

#[test]
fn test_header_deadline_rejects_zero_and_accepts_finite_duration() {
  assert!(serde_yaml::from_str::<HeaderDeadline>("100ms").is_ok());
  assert!(serde_yaml::from_str::<HeaderDeadline>("0s").is_err());
}
