//! Black-box tests for the service module.

use crate::server::placeholder_service;
use crate::service::Layer;

#[derive(Clone)]
struct TestMiddleware {
  inner: crate::service::Service,
}

impl tower::Service<crate::http_message::Request> for TestMiddleware {
  type Error = anyhow::Error;
  type Future = std::pin::Pin<
    Box<
      dyn std::future::Future<
          Output = anyhow::Result<crate::http_message::Response>,
        >,
    >,
  >;
  type Response = crate::http_message::Response;

  fn poll_ready(
    &mut self,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(
    &mut self,
    req: crate::http_message::Request,
  ) -> Self::Future {
    self.inner.call(req)
  }
}

struct TestLayer;

impl tower::Layer<crate::service::Service> for TestLayer {
  type Service = crate::service::Service;

  fn layer(&self, inner: crate::service::Service) -> Self::Service {
    crate::service::Service::new(TestMiddleware { inner })
  }
}

#[test]
fn test_layer_wraps_service() {
  let inner = placeholder_service();
  let layer = Layer::new(TestLayer);
  let _wrapped = layer.layer(inner);
  // Wrapped service is created successfully
}

#[test]
fn test_layer_preserves_composed_authentication_through_cloning() {
  struct Verifier;
  impl crate::authentication::CredentialVerifier for Verifier {
    fn accepts(&self, username: &str, password: &str) -> bool {
      username == "user" && password == "secret"
    }
  }
  let layer = Layer::with_authentication(
    TestLayer,
    std::sync::Arc::new(Verifier),
  );
  let service = layer.layer(placeholder_service());
  let service = Layer::new(TestLayer).layer(service).clone();
  let authentication = service.authentication();
  assert!(authentication.requires_credentials());
  assert!(authentication.accepts("user", "secret"));
  assert!(!authentication.accepts("user", "wrong"));
}
