use base64::Engine;

pub(crate) fn apply_proxy_auth(
  user: &Option<crate::config::UserCredential>,
  req: &mut http::Request<()>,
) {
  if let Some(user) = user {
    let credentials = base64::engine::general_purpose::STANDARD
      .encode(format!("{}:{}", user.username, user.password));
    req.headers_mut().insert(
      "Proxy-Authorization",
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap(),
    );
  }
}
