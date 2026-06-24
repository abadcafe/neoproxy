use super::listener_args_fixture::empty_args;

#[test]
fn test_empty_args_returns_empty_mapping() {
  let args = empty_args();

  assert!(args.as_mapping().unwrap().is_empty());
}
