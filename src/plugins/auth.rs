//! Auth plugin.

pub mod auth_type;
pub mod user_password_auth;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub use auth_type::AuthType;
pub use user_password_auth::UserPasswordAuth;

use crate::config::SerializedArgs;
use crate::context::RequestContext;
use crate::http_utils::{
  BytesBufBodyWrapper, Request, Response, ResponseBody,
};
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer, Service};

/// Parse Proxy-Authorization header (Basic Auth).
/// Returns (username, password) or None if invalid.
/// Delegates to `UserPasswordAuth::parse_basic_auth` to avoid
/// duplication.
pub fn parse_basic_auth_header(
  header: &http::HeaderValue,
) -> Option<(String, String)> {
  UserPasswordAuth::parse_basic_auth(header).ok()
}

/// Build a 407 Proxy Authentication Required response.
pub fn build_407_response() -> Response {
  let empty = http_body_util::Empty::new();
  let bytes_buf = BytesBufBodyWrapper::new(empty);
  let body = ResponseBody::new(bytes_buf);
  let mut resp = Response::new(body);
  *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
  resp.headers_mut().insert(
    http::header::PROXY_AUTHENTICATE,
    http::HeaderValue::from_static("Basic realm=\"proxy\""),
  );
  resp
}

/// Auth plugin that provides basic_auth layer.
pub struct AuthPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
}

impl AuthPlugin {
  pub fn new() -> Self {
    let basic_auth_builder: Box<dyn BuildLayer> =
      Box::new(|args: SerializedArgs| {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AuthConfig {
          users: Vec<crate::config::UserCredential>,
        }

        let config: AuthConfig = serde_yaml::from_value(args)?;
        let auth = user_password_auth::UserPasswordAuth::from_users(
          &config.users,
        );
        Ok(Layer::new(AuthLayer { auth }))
      });

    let layer_builders =
      HashMap::from([("basic_auth", basic_auth_builder)]);

    Self { layer_builders }
  }
}

impl Plugin for AuthPlugin {
  fn layer_builder(&self, name: &str) -> Option<&Box<dyn BuildLayer>> {
    self.layer_builders.get(name)
  }
}

pub fn plugin_name() -> &'static str {
  "auth"
}

pub fn create_plugin() -> Box<dyn Plugin> {
  Box::new(AuthPlugin::new())
}

/// Layer that creates AuthMiddleware instances.
struct AuthLayer {
  auth: user_password_auth::UserPasswordAuth,
}

impl tower::Layer<Service> for AuthLayer {
  type Service = Service;

  fn layer(&self, inner: Service) -> Service {
    Service::new(AuthMiddleware { inner, auth: self.auth.clone() })
  }
}

/// Middleware that checks Proxy-Authorization header.
#[derive(Clone)]
struct AuthMiddleware {
  inner: Service,
  auth: user_password_auth::UserPasswordAuth,
}

impl tower::Service<Request> for AuthMiddleware {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = anyhow::Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    let ctx = match req.extensions().get::<RequestContext>().cloned() {
      Some(ctx) => ctx,
      None => {
        return Box::pin(async { Ok(build_407_response()) });
      }
    };

    if let Some(auth_header) = req.headers().get("Proxy-Authorization")
      && let Some((username, password)) =
        parse_basic_auth_header(auth_header)
      && self.auth.verify_credentials(&username, &password).is_ok()
    {
      ctx.insert("auth.basic_auth.user", username);
      ctx.insert(
        "auth.basic_auth.auth_type",
        AuthType::Password.to_string(),
      );

      let mut inner = self.inner.clone();
      return Box::pin(async move { inner.call(req).await });
    }

    Box::pin(async move { Ok(build_407_response()) })
  }
}

#[cfg(test)]
mod parse_tests {
  use base64::Engine;
  use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

  #[test]
  fn test_parse_basic_auth_valid() {
    let credentials = BASE64_STANDARD.encode("admin:secret");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      crate::plugins::auth::parse_basic_auth_header(&header).unwrap();
    assert_eq!(user, "admin");
    assert_eq!(pass, "secret");
  }

  #[test]
  fn test_parse_basic_auth_no_basic_prefix() {
    let header =
      http::HeaderValue::from_str("Bearer token123").unwrap();
    assert!(
      crate::plugins::auth::parse_basic_auth_header(&header).is_none()
    );
  }

  #[test]
  fn test_parse_basic_auth_invalid_base64() {
    let header =
      http::HeaderValue::from_str("Basic not-valid-base64!!!").unwrap();
    assert!(
      crate::plugins::auth::parse_basic_auth_header(&header).is_none()
    );
  }

  #[test]
  fn test_parse_basic_auth_no_colon() {
    let credentials = BASE64_STANDARD.encode("nocolon");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    assert!(
      crate::plugins::auth::parse_basic_auth_header(&header).is_none()
    );
  }

  #[test]
  fn test_parse_basic_auth_empty_username() {
    let credentials = BASE64_STANDARD.encode(":password");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    assert!(
      crate::plugins::auth::parse_basic_auth_header(&header).is_none()
    );
  }

  #[test]
  fn test_parse_basic_auth_empty_password() {
    let credentials = BASE64_STANDARD.encode("user:");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      crate::plugins::auth::parse_basic_auth_header(&header).unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "");
  }

  #[test]
  fn test_parse_basic_auth_password_with_colon() {
    let credentials = BASE64_STANDARD.encode("user:pass:word");
    let header =
      http::HeaderValue::from_str(&format!("Basic {}", credentials))
        .unwrap();
    let (user, pass) =
      crate::plugins::auth::parse_basic_auth_header(&header).unwrap();
    assert_eq!(user, "user");
    assert_eq!(pass, "pass:word");
  }
}

#[cfg(test)]
mod response_tests {
  #[test]
  fn test_build_407_response() {
    let resp = crate::plugins::auth::build_407_response();
    assert_eq!(
      resp.status(),
      http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert_eq!(
      resp
        .headers()
        .get("Proxy-Authenticate")
        .unwrap()
        .to_str()
        .unwrap(),
      "Basic realm=\"proxy\""
    );
  }
}

#[cfg(test)]
mod plugin_tests {
  use crate::plugin::Plugin;

  #[test]
  fn test_auth_plugin_has_basic_auth_layer() {
    let plugin = crate::plugins::auth::AuthPlugin::new();
    assert!(plugin.layer_builder("basic_auth").is_some());
  }

  #[test]
  fn test_auth_plugin_no_unknown_layer() {
    let plugin = crate::plugins::auth::AuthPlugin::new();
    assert!(plugin.layer_builder("unknown").is_none());
  }

  #[test]
  fn test_auth_plugin_no_service_builder() {
    let plugin = crate::plugins::auth::AuthPlugin::new();
    assert!(plugin.service_builder("any").is_none());
  }

  #[test]
  fn test_auth_plugin_name() {
    assert_eq!(crate::plugins::auth::plugin_name(), "auth");
  }

  #[test]
  fn test_auth_plugin_create_plugin() {
    let plugin = crate::plugins::auth::create_plugin();
    assert!(plugin.layer_builder("basic_auth").is_some());
  }
}

#[cfg(test)]
mod integration_tests {
  use super::*;

  #[test]
  fn test_basic_auth_layer_builder_valid_args() {
    let plugin = AuthPlugin::new();
    let builder = plugin.layer_builder("basic_auth").unwrap();

    let args: SerializedArgs = serde_yaml::from_str(
      r#"
users:
  - username: admin
    password: secret
"#,
    )
    .unwrap();

    let layer = builder(args).unwrap();
    let inner = crate::server::placeholder_service();
    let _wrapped = layer.layer(inner);
  }

  #[test]
  fn test_basic_auth_layer_builder_empty_users() {
    let plugin = AuthPlugin::new();
    let builder = plugin.layer_builder("basic_auth").unwrap();

    let args: SerializedArgs = serde_yaml::from_str(
      r#"
users: []
"#,
    )
    .unwrap();

    let layer = builder(args).unwrap();
    let inner = crate::server::placeholder_service();
    let _wrapped = layer.layer(inner);
  }
}

#[cfg(test)]
mod middleware_tests {
  use base64::Engine;
  use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
  use http_body_util::BodyExt;
  use tower::Service as TowerService;

  use super::*;
  use crate::context::RequestContext;
  use crate::http_utils::RequestBody;

  /// Helper to build a request with a RequestContext extension.
  fn make_request_with_ctx(
    proxy_auth: Option<&str>,
  ) -> crate::http_utils::Request {
    let body: RequestBody =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();

    let mut builder = http::Request::builder();
    if let Some(auth) = proxy_auth {
      builder = builder.header("Proxy-Authorization", auth);
    }
    let mut req = builder.body(body).unwrap();
    req.extensions_mut().insert(RequestContext::new());
    req
  }

  /// Build a valid Basic auth header value.
  fn basic_auth_header(user: &str, pass: &str) -> String {
    let credentials =
      BASE64_STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", credentials)
  }

  /// Create a middleware-wrapped service with configured users.
  fn make_middleware_service() -> crate::service::Service {
    let users = vec![crate::config::UserCredential {
      username: "admin".to_string(),
      password: "secret".to_string(),
    }];
    let auth = UserPasswordAuth::from_users(&users);
    let layer = crate::service::Layer::new(AuthLayer { auth });
    let inner = crate::server::placeholder_service();
    layer.layer(inner)
  }

  #[test]
  fn test_missing_auth_header_returns_407() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      let req = make_request_with_ctx(None);
      let resp = svc.call(req).await.unwrap();
      assert_eq!(
        resp.status(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
      );
    });
  }

  #[test]
  fn test_invalid_credentials_returns_407() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      let auth = basic_auth_header("admin", "wrongpassword");
      let req = make_request_with_ctx(Some(&auth));
      let resp = svc.call(req).await.unwrap();
      assert_eq!(
        resp.status(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
      );
    });
  }

  #[test]
  fn test_unknown_user_returns_407() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      let auth = basic_auth_header("unknown", "pass");
      let req = make_request_with_ctx(Some(&auth));
      let resp = svc.call(req).await.unwrap();
      assert_eq!(
        resp.status(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
      );
    });
  }

  #[test]
  fn test_valid_credentials_passes_through() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      let auth = basic_auth_header("admin", "secret");
      let req = make_request_with_ctx(Some(&auth));
      let resp = svc.call(req).await;
      // placeholder_service returns an error, so we expect Err
      // (proving the request was forwarded to the inner service)
      assert!(resp.is_err());
    });
  }

  #[test]
  fn test_valid_credentials_sets_context() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let ctx = RequestContext::new();
      let ctx_clone = ctx.clone();

      let users = vec![crate::config::UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }];
      let auth = UserPasswordAuth::from_users(&users);
      let layer = crate::service::Layer::new(AuthLayer { auth });
      let inner = crate::server::placeholder_service();
      let mut svc = layer.layer(inner);

      let body: RequestBody =
        http_body_util::Empty::<bytes::Bytes>::new()
          .map_err(|e: std::convert::Infallible| {
            anyhow::anyhow!("{}", e)
          })
          .boxed_unsync();

      let auth_header = basic_auth_header("admin", "secret");
      let mut req = http::Request::builder()
        .header("Proxy-Authorization", &auth_header)
        .body(body)
        .unwrap();
      req.extensions_mut().insert(ctx_clone);

      // The call will fail (placeholder), but we can check context
      let _ = svc.call(req).await;

      // Check that auth info was written to the context
      assert_eq!(
        ctx.get("auth.basic_auth.user"),
        Some("admin".to_string())
      );
      assert_eq!(
        ctx.get("auth.basic_auth.auth_type"),
        Some("password".to_string())
      );
    });
  }

  #[test]
  fn test_407_has_proxy_authenticate_header() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      let req = make_request_with_ctx(None);
      let resp = svc.call(req).await.unwrap();
      assert_eq!(
        resp
          .headers()
          .get("Proxy-Authenticate")
          .unwrap()
          .to_str()
          .unwrap(),
        "Basic realm=\"proxy\""
      );
    });
  }

  #[test]
  fn test_valid_credentials_returns_inner_response() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      // Create an inner service that returns a successful response
      let inner = crate::service::Service::new(tower::service_fn(
        |_req: crate::http_utils::Request| {
          Box::pin(async {
            let body: crate::http_utils::ResponseBody =
              http_body_util::Full::new(bytes::Bytes::from("hello"))
                .map_err(|e: std::convert::Infallible| {
                  anyhow::anyhow!("{}", e)
                })
                .boxed_unsync();
            let mut resp = crate::http_utils::Response::new(body);
            *resp.status_mut() = http::StatusCode::OK;
            Ok::<_, anyhow::Error>(resp)
          })
            as std::pin::Pin<
              Box<
                dyn std::future::Future<
                    Output = anyhow::Result<
                      crate::http_utils::Response,
                    >,
                  >,
              >,
            >
        },
      ));

      let users = vec![crate::config::UserCredential {
        username: "admin".to_string(),
        password: "secret".to_string(),
      }];
      let auth = UserPasswordAuth::from_users(&users);
      let layer = crate::service::Layer::new(AuthLayer { auth });
      let mut svc = layer.layer(inner);

      let auth = basic_auth_header("admin", "secret");
      let req = make_request_with_ctx(Some(&auth));
      let resp = svc.call(req).await.unwrap();
      // The inner service returns 200 OK, proving the request was
      // forwarded after successful authentication
      assert_eq!(resp.status(), http::StatusCode::OK);
    });
  }

  #[test]
  fn test_missing_request_context_returns_error() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
      let mut svc = make_middleware_service();
      // Build request WITHOUT RequestContext extension
      let body: RequestBody =
        http_body_util::Empty::<bytes::Bytes>::new()
          .map_err(|e: std::convert::Infallible| {
            anyhow::anyhow!("{}", e)
          })
          .boxed_unsync();
      let req = http::Request::builder().body(body).unwrap();
      // Should NOT panic, should return 407 gracefully
      let resp = svc.call(req).await.unwrap();
      assert_eq!(
        resp.status(),
        http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
      );
    });
  }
}
