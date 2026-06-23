//! Black-box tests for the service module.

use crate::server::placeholder_service;
use crate::service::Layer;

#[derive(Clone)]
struct TestMiddleware {
  inner: crate::service::Service,
}

impl tower::Service<crate::http_utils::Request> for TestMiddleware {
  type Error = anyhow::Error;
  type Future = std::pin::Pin<
    Box<
      dyn std::future::Future<
          Output = anyhow::Result<crate::http_utils::Response>,
        >,
    >,
  >;
  type Response = crate::http_utils::Response;

  fn poll_ready(
    &mut self,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<anyhow::Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: crate::http_utils::Request) -> Self::Future {
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
