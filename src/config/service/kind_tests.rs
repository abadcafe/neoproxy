use super::kind::parse_plugin_kind;
#[test]
fn test_parse_plugin_kind_requires_two_nonempty_components() {
  assert_eq!(
    parse_plugin_kind("auth.basic_auth", "layer").unwrap(),
    ("auth".into(), "basic_auth".into())
  );
  for invalid in ["", "auth", ".auth", "auth.", "auth.basic.extra"] {
    assert!(parse_plugin_kind(invalid, "layer").is_err());
  }
}
