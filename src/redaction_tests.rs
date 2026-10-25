//! Black-box tests for diagnostic parameter redaction.

use std::collections::HashMap;

use crate::redaction::Redacted;

#[test]
fn test_debug_preserves_non_secret_yaml_in_both_formats() {
  let value: serde_yaml::Value = serde_yaml::from_str(
    "username: alice\naddress: localhost\ntoken_count: 3\nkey_path: \
     /cert/key.pem\npayload: [null, true, 2, text]\nnumeric: {1: one, \
     false: two}\ntagged: !custom {visible: yes}",
  )
  .unwrap();
  assert_eq!(format!("{:?}", Redacted(&value)), format!("{value:?}"));
  assert_eq!(format!("{:#?}", Redacted(&value)), format!("{value:#?}"));
}

#[test]
fn test_debug_masks_nested_password_and_token_fields() {
  let value: serde_yaml::Value = serde_yaml::from_str(
    "users: [{username: alice, password: hidden-password}]\nnested: \
     !custom {ToKeN: hidden-token, access_token: hidden-access, \
     client-password: hidden-client}\nordinary: hidden-password",
  )
  .unwrap();
  for output in [
    format!("{:?}", Redacted(&value)),
    format!("{:#?}", Redacted(&value)),
  ] {
    assert!(output.contains("alice"));
    assert!(output.contains("ToKeN"));
    assert!(output.contains("access_token"));
    assert!(output.contains("client-password"));
    assert!(!output.contains("hidden-token"));
    assert!(!output.contains("hidden-access"));
    assert!(!output.contains("hidden-client"));
    // Redaction follows field names, never matches text globally.
    assert_eq!(output.matches("hidden-password").count(), 1);
    assert_eq!(output.matches("\"*\"").count(), 4);
  }
  assert_eq!(
    value["users"][0]["password"].as_str(),
    Some("hidden-password")
  );
}

#[test]
fn test_debug_masks_entire_blacklisted_value_regardless_of_type() {
  let value: serde_yaml::Value = serde_yaml::from_str(
    "password: {nested: hidden}\ntoken: [one, two]\nPASSWORD: \
     null\nTOKEN: 123",
  )
  .unwrap();
  for output in [
    format!("{:?}", Redacted(&value)),
    format!("{:#?}", Redacted(&value)),
  ] {
    assert_eq!(output.matches("\"*\"").count(), 4);
    for hidden in ["nested", "hidden", "one", "two", "Null", "123"] {
      assert!(!output.contains(hidden));
    }
  }
}

#[test]
fn test_debug_plugin_map_preserves_names_and_masks_nested_tokens() {
  let value = serde_yaml::from_str::<serde_yaml::Value>(
    "username: alice\nrefresh_token: hidden-refresh",
  )
  .unwrap();
  let plugins = HashMap::from([("plugin-name".to_string(), value)]);
  for output in [
    format!("{:?}", Redacted(&plugins)),
    format!("{:#?}", Redacted(&plugins)),
  ] {
    assert!(output.contains("plugin-name"));
    assert!(output.contains("alice"));
    assert!(output.contains("refresh_token"));
    assert!(output.contains("\"*\""));
    assert!(!output.contains("hidden-refresh"));
  }
}

#[test]
fn test_debug_password_map_preserves_usernames() {
  let users = HashMap::from([
    ("alice".to_string(), "hidden-alice".to_string()),
    ("token".to_string(), "hidden-token-user-password".to_string()),
  ]);
  for output in [
    format!("{:?}", Redacted(&users)),
    format!("{:#?}", Redacted(&users)),
  ] {
    assert!(output.contains("alice"));
    assert!(output.contains("token"));
    assert!(!output.contains("hidden-"));
    assert_eq!(output.matches("\"*\"").count(), 2);
  }
  assert_eq!(users["alice"], "hidden-alice");
}
