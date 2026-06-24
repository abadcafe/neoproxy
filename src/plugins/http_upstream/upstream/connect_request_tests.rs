use http_body_util::BodyExt;

use super::connect_request::build_connect_request;

fn user_credential(
  username: &str,
  password: &str,
) -> crate::config::UserCredential {
  serde_yaml::from_str(&format!(
    "username: {username:?}\npassword: {password:?}\n"
  ))
  .unwrap()
}

#[tokio::test]
async fn test_build_connect_request_sets_method_uri_host_and_empty_body()
 {
  let req = build_connect_request("example.com:443", &None);

  assert_eq!(req.method(), http::Method::CONNECT);
  assert_eq!(req.uri(), "example.com:443");
  assert_eq!(
    req.headers().get(http::header::HOST).unwrap(),
    "example.com:443"
  );
  assert!(
    req.into_body().collect().await.unwrap().to_bytes().is_empty()
  );
}

#[test]
fn test_build_connect_request_applies_proxy_auth() {
  let user = Some(user_credential("alice", "secret"));

  let req = build_connect_request("example.com:443", &user);

  assert_eq!(
    req.headers().get("Proxy-Authorization").unwrap(),
    "Basic YWxpY2U6c2VjcmV0"
  );
}
