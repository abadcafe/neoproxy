use super::connect_request::build_connect_request;
use crate::plugins::upstream::target_parser::{
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

#[test]
fn test_build_connect_request_sets_context_id_after_hop_header_cleaning()
 {
  let mut source = http::Request::builder()
    .header("connection", "x-request-id")
    .header("x-request-id", "wrong-header")
    .body(())
    .unwrap();
  let mut identity = http::HeaderMap::new();
  identity.insert("x-request-id", "context-id".parse().unwrap());
  let context = crate::context::RequestContext::new().with_request_id(
    crate::request_id::RequestId::read_or_generate(&identity).unwrap(),
  );
  source.extensions_mut().insert(context);
  let result = build_connect_request(
    &connect_target("example.com:443"),
    &None,
    &source.into_parts().0,
  );
  assert_eq!(result.headers()["x-request-id"], "context-id");
  assert!(!result.headers().contains_key("connection"));
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

#[test]
fn test_build_connect_request_sets_method_uri_host_without_transport_body()
 {
  let target = connect_target("example.com:443");
  let req: http::Request<()> = build_connect_request(
    &target,
    &None,
    &http::Request::new(()).into_parts().0,
  );

  assert_eq!(req.method(), http::Method::CONNECT);
  assert_eq!(req.uri(), "example.com:443");
  assert_eq!(
    req.headers().get(http::header::HOST).unwrap(),
    "example.com:443"
  );
}

#[test]
fn test_build_connect_request_applies_proxy_auth() {
  let user = Some(user_credential("alice", "secret"));

  let target = connect_target("example.com:443");
  let req = build_connect_request(
    &target,
    &user,
    &http::Request::new(()).into_parts().0,
  );

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
    let req = build_connect_request(
      &target,
      &None,
      &http::Request::new(()).into_parts().0,
    );
    assert_eq!(req.uri(), authority);
    assert_eq!(req.headers()[http::header::HOST], authority);
  }
}
