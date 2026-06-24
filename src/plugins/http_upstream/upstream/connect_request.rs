use crate::http_message::{BytesBufBodyWrapper, RequestBody};

pub(crate) fn build_connect_request(
  target: &str,
  user: &Option<crate::config::UserCredential>,
) -> http::Request<RequestBody> {
  let mut req = http::Request::builder()
    .method(http::Method::CONNECT)
    .uri(target)
    .header(http::header::HOST, target)
    .body(())
    .expect("building CONNECT request should not fail");
  super::proxy_auth::apply_proxy_auth(user, &mut req);
  let empty = http_body_util::Empty::new();
  let wrapped = BytesBufBodyWrapper::new(empty);
  let body = RequestBody::new(wrapped);
  let (parts, _) = req.into_parts();
  http::Request::from_parts(parts, body)
}
