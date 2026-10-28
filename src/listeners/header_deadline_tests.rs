use super::header_deadline::HeaderDeadline;

#[test]
fn test_header_deadline_rejects_zero_and_accepts_finite_duration() {
  assert!(serde_yaml::from_str::<HeaderDeadline>("100ms").is_ok());
  assert!(serde_yaml::from_str::<HeaderDeadline>("0s").is_err());
}

#[test]
fn test_header_deadline_default_is_seventy_five_seconds() {
  assert_eq!(
    HeaderDeadline::default().duration(),
    std::time::Duration::from_secs(75)
  );
}
