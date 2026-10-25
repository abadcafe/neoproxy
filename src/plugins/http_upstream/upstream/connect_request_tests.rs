use http_body_util::BodyExt;

use super::connect_request::build_connect_request;
use crate::plugins::http_upstream::target_parser::{
  ConnectTarget, parse_connect_target,
};

fn connect_target(authority: &str) -> ConnectTarget {
  let request = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(authority)
    .body(())
    .unwrap();
  parse_connect_target(&request.into_parts().0).unwrap()
}

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
  let target = connect_target("example.com:443");
  let req = build_connect_request(&target, &None);

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

  let target = connect_target("example.com:443");
  let req = build_connect_request(&target, &user);

  assert_eq!(
    req.headers().get("Proxy-Authorization").unwrap(),
    "Basic YWxpY2U6c2VjcmV0"
  );
}

#[test]
fn test_build_connect_request_preserves_authority_and_port_boundaries()
{
  for authority in
    ["127.0.0.1:1", "[2001:db8::1]:65535", "EXAMPLE.COM:00443"]
  {
    let target = connect_target(authority);
    let req = build_connect_request(&target, &None);
    assert_eq!(req.uri(), authority);
    assert_eq!(req.headers()[http::header::HOST], authority);
  }
}
