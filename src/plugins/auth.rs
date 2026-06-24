//! Auth plugin — proxy basic authentication.
//!
//! module: auth
//! responsibilities: proxy authentication via Basic Auth header
//! public operations: plugin_name, create_plugin
//! data entities: AuthPlugin, AuthLayer, AuthType
//! tests: auth_tests.rs

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;

use crate::auth::UserPasswordAuth;

/// Authentication type used for the request.
/// Internal to auth plugin - written as string to RequestContext.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AuthType {
  #[default]
  None,
  Password,
}

impl std::fmt::Display for AuthType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      AuthType::None => write!(f, "none"),
      AuthType::Password => write!(f, "password"),
    }
  }
}

use crate::config::SerializedArgs;
use crate::context::RequestContext;
use crate::http_message::{
  BytesBufBodyWrapper, Request, Response, ResponseBody,
};
use crate::plugin::Plugin;
use crate::service::{BuildLayer, Layer, Service};

/// Parse Proxy-Authorization header (Basic Auth).
/// Returns (username, password) or None if invalid.
/// Delegates to `UserPasswordAuth::parse_basic_auth` to avoid
/// duplication.
pub(crate) fn parse_basic_auth_header(
  header: &http::HeaderValue,
) -> Option<(String, String)> {
  UserPasswordAuth::parse_basic_auth(header).ok()
}

/// Build a 407 Proxy Authentication Required response.
pub(crate) fn build_407_response() -> Response {
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
pub(crate) struct AuthPlugin {
  layer_builders: HashMap<&'static str, Box<dyn BuildLayer>>,
}

impl AuthPlugin {
  pub(crate) fn new() -> Self {
    let basic_auth_builder: Box<dyn BuildLayer> =
      Box::new(|args: SerializedArgs| {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AuthConfig {
          users: Vec<crate::config::UserCredential>,
        }

        let config: AuthConfig = serde_yaml::from_value(args)?;
        let auth = UserPasswordAuth::from_users(&config.users);
        Ok(Layer::new(AuthLayer { auth }))
      });

    let layer_builders =
      HashMap::from([("basic_auth", basic_auth_builder)]);

    Self { layer_builders }
  }
}

impl Plugin for AuthPlugin {
  fn layer_builder(&self, name: &str) -> Option<&dyn BuildLayer> {
    self.layer_builders.get(name).map(|b| b.as_ref())
  }
}

pub fn plugin_name() -> &'static str {
  "auth"
}

pub fn create_plugin(
  _config: Option<&SerializedArgs>,
) -> Result<Box<dyn Plugin>> {
  Ok(Box::new(AuthPlugin::new()))
}

/// Layer that creates AuthMiddleware instances.
pub(crate) struct AuthLayer {
  pub(crate) auth: UserPasswordAuth,
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
  auth: UserPasswordAuth,
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
      ctx.insert("basic_auth.user", username);
      ctx
        .insert("basic_auth.auth_type", AuthType::Password.to_string());

      let mut inner = self.inner.clone();
      return Box::pin(async move { inner.call(req).await });
    }

    Box::pin(async move { Ok(build_407_response()) })
  }
}
