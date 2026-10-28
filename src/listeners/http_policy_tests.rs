use super::http_policy::HttpPolicy;
#[test]
fn test_http_policy_defaults_and_invalid_deadlines() {
  let policy = HttpPolicy::default();
  assert_eq!(policy.body_read_timeout.duration().as_secs(), 60);
  assert_eq!(policy.write_timeout.duration().as_secs(), 60);
  for yaml in ["body_read_timeout: 0s", "write_timeout: 0s"] {
    assert!(serde_yaml::from_str::<HttpPolicy>(yaml).is_err());
  }
}
