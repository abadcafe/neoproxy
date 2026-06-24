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
