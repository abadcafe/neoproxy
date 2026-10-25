use super::auth::*;

#[test]
fn test_user_credential_deserialize() {
  let yaml = r#"
username: "admin"
password: "secret"
"#;
  let user: UserCredential = serde_yaml::from_str(yaml).unwrap();
  assert_eq!(user.username(), "admin");
  assert_eq!(user.password(), "secret");
}

#[test]
fn test_user_credential_debug_only_masks_password() {
  let user: UserCredential = serde_yaml::from_str(
    "username: visible-user\npassword: hidden-password",
  )
  .unwrap();
  for output in [format!("{user:?}"), format!("{user:#?}")] {
    assert!(output.contains("username: \"visible-user\""));
    assert!(output.contains("password: \"*\""));
    assert!(!output.contains("hidden-password"));
  }
  assert_eq!(user.password(), "hidden-password");
}
