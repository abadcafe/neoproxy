use super::proxy_auth::{apply_proxy_auth, consume_proxy_auth_headers};

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
fn test_apply_proxy_auth_without_user_leaves_proxy_credentials_absent()
{
  let mut req = http::Request::builder().body(()).unwrap();

  apply_proxy_auth(&None, &mut req);

  assert!(req.headers().get("Proxy-Authorization").is_none());
}

#[test]
fn test_apply_proxy_auth_without_user_consumes_previous_hop_credentials()
 {
  let mut req = http::Request::builder()
    .header(http::header::PROXY_AUTHORIZATION, "Basic client-secret")
    .header("x-end-to-end", "keep")
    .body(())
    .unwrap();
  apply_proxy_auth(&None, &mut req);
  assert!(
    !req.headers().contains_key(http::header::PROXY_AUTHORIZATION)
  );
  assert_eq!(req.headers()["x-end-to-end"], "keep");
}

#[test]
fn test_apply_proxy_auth_replaces_previous_hop_credentials() {
  let mut req = http::Request::builder()
    .header(http::header::PROXY_AUTHORIZATION, "Basic client-secret")
    .body(())
    .unwrap();
  apply_proxy_auth(&Some(user_credential("alice", "secret")), &mut req);
  assert_eq!(
    req.headers()[http::header::PROXY_AUTHORIZATION],
    "Basic YWxpY2U6c2VjcmV0"
  );
  assert_eq!(
    req
      .headers()
      .get_all(http::header::PROXY_AUTHORIZATION)
      .iter()
      .count(),
    1
  );
}

#[test]
fn test_consume_proxy_auth_headers_preserves_origin_authentication() {
  let mut headers = http::HeaderMap::new();
  headers.insert(
    http::header::PROXY_AUTHORIZATION,
    "Basic hop-secret".parse().unwrap(),
  );
  headers.insert(
    http::header::PROXY_AUTHENTICATE,
    "Basic realm=\"hop\"".parse().unwrap(),
  );
  headers.insert(
    http::header::WWW_AUTHENTICATE,
    "Basic realm=\"origin\"".parse().unwrap(),
  );
  headers.insert(
    http::header::AUTHORIZATION,
    "Bearer origin-token".parse().unwrap(),
  );
  consume_proxy_auth_headers(&mut headers);
  assert!(!headers.contains_key(http::header::PROXY_AUTHORIZATION));
  assert!(!headers.contains_key(http::header::PROXY_AUTHENTICATE));
  assert_eq!(
    headers[http::header::WWW_AUTHENTICATE],
    "Basic realm=\"origin\""
  );
  assert_eq!(
    headers[http::header::AUTHORIZATION],
    "Bearer origin-token"
  );
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
