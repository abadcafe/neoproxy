//! Runtime service types.
//!
//! This module provides types for building and managing request
//! handlers:
//! - `Service` - A wrapper type for any tower::Service implementation
//! - `BuildService` - Factory trait for creating services

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;

use crate::config::SerializedArgs;
use crate::http_utils::{Request, Response};

/// Internal trait for cloning services.
///
/// This allows `Service` to be cloneable even though `tower::Service`
/// doesn't require `Clone`. Only auto traits like `Send`, `Sync`
/// can be added to type definitions, so we need this helper trait.
trait CloneService:
  tower::Service<
    Request,
    Error = anyhow::Error,
    Response = Response,
    Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
  >
{
  fn clone_boxed(&self) -> Box<dyn CloneService>;
}

impl<S> CloneService for S
where
  S: tower::Service<
      Request,
      Error = anyhow::Error,
      Response = Response,
      Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
    > + Clone
    + 'static,
{
  fn clone_boxed(&self) -> Box<dyn CloneService> {
    Box::new(self.clone())
  }
}

/// A type-erased service wrapper.
///
/// Wraps any `tower::Service` implementation. Created by `BuildService`
/// functions. The service is non-`Sync` but `Clone`, allowing it to
/// be cloned and created temporarily (even per-request).
///
/// **Note:** This is the *runtime* service type, not to be confused
/// with `config::Service` which represents configuration data.
pub struct Service(Box<dyn CloneService>);

impl Service {
  /// Create a new service from a tower::Service implementation.
  pub fn new<S>(inner: S) -> Self
  where
    S: tower::Service<
        Request,
        Response = Response,
        Error = anyhow::Error,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Clone
      + 'static,
  {
    Self(Box::new(inner))
  }
}

impl tower::Service<Request> for Service {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = Response;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
    self.0.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    self.0.call(req)
  }
}

impl Clone for Service {
  fn clone(&self) -> Self {
    Self(self.0.clone_boxed())
  }
}

impl std::fmt::Debug for Service {
  fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
    fmt.debug_struct("Service").finish()
  }
}

/// Factory trait for building services.
///
/// A `BuildService` is a function that takes configuration arguments
/// and returns a `Service`.
pub trait BuildService: Fn(SerializedArgs) -> Result<Service> {}

impl<F> BuildService for F where F: Fn(SerializedArgs) -> Result<Service>
{}

/// A layer that wraps a Service to produce another Service.
pub struct Layer(
  Box<dyn tower::Layer<Service, Service = Service> + 'static>,
);

impl Layer {
  pub fn new<L>(layer: L) -> Self
  where
    L: tower::Layer<Service, Service = Service> + 'static,
  {
    Self(Box::new(layer))
  }

  pub fn layer(&self, inner: Service) -> Service {
    self.0.layer(inner)
  }
}

/// Factory trait for building layers.
pub trait BuildLayer: Fn(SerializedArgs) -> Result<Layer> {}
impl<F> BuildLayer for F where F: Fn(SerializedArgs) -> Result<Layer> {}

#[cfg(test)]
mod layer_tests {
  use super::*;

  #[derive(Clone)]
  struct TestMiddleware {
    inner: Service,
  }

  impl tower::Service<Request> for TestMiddleware {
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response>>>>;
    type Response = Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
      self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
      self.inner.call(req)
    }
  }

  struct TestLayer;

  impl tower::Layer<Service> for TestLayer {
    type Service = Service;

    fn layer(&self, inner: Service) -> Self::Service {
      Service::new(TestMiddleware { inner })
    }
  }

  #[test]
  fn test_layer_new() {
    let layer = Layer::new(TestLayer);
    // Just verify it can be created
    let _ = layer;
  }

  #[test]
  fn test_layer_wraps_service() {
    let inner = crate::server::placeholder_service();
    let layer = Layer::new(TestLayer);
    let _wrapped = layer.layer(inner);
    // Wrapped service is created successfully
  }
}
