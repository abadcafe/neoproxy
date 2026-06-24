use super::proxy_auth::apply_proxy_auth;

fn user_credential(
  username: &str,
  password: &str,
) -> crate::config::UserCredential {
  serde_yaml::from_str(&format!(
    "username: {username:?}\npassword: {password:?}\n"
  ))
  .unwrap()
}

#[test]
fn test_apply_proxy_auth_without_user_leaves_headers_unchanged() {
  let mut req = http::Request::builder().body(()).unwrap();

  apply_proxy_auth(&None, &mut req);

  assert!(req.headers().get("Proxy-Authorization").is_none());
}

#[test]
fn test_apply_proxy_auth_with_user_sets_basic_header() {
  let mut req = http::Request::builder().body(()).unwrap();
  let user = Some(user_credential("alice", "secret"));

  apply_proxy_auth(&user, &mut req);

  assert_eq!(
    req.headers().get("Proxy-Authorization").unwrap(),
    "Basic YWxpY2U6c2VjcmV0"
  );
}
