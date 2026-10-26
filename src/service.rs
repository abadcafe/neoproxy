//! module: service
//! responsibility: define type-erased service composition contracts
//! public operations: Service, new, authentication, BuildService,
//! Layer, with_authentication, layer, BuildLayer
//! data entities: Service, Layer
//! tests: service_tests.rs

//! Runtime service types.
//!
//! This module provides types for building and managing request
//! handlers:
//! - `Service` - A wrapper type for any tower::Service implementation
//! - `BuildService` - Factory trait for creating services

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;

use crate::authentication::{Authentication, CredentialVerifier};
use crate::config::SerializedArgs;
use crate::http_message::{Request, Response};

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
///
/// Returning a Response completes the service call, not necessarily
/// the exchange: its body may still be streaming. The listener's HTTP
/// driver owns transport shutdown until an upgrade transfers I/O to
/// a separately managed tunnel task.
/// Authentication layers explicitly contribute transport-independent
/// credential requirements during composition. Protocol adapters use
/// that public contract for authentication handshakes; complete
/// requests still pass through the configured middleware.
pub(crate) struct Service {
  inner: Box<dyn CloneService>,
  authentication: Authentication,
}

impl Service {
  /// Create a new service from a tower::Service implementation.
  pub(crate) fn new<S>(inner: S) -> Self
  where
    S: tower::Service<
        Request,
        Response = Response,
        Error = anyhow::Error,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Clone
      + 'static,
  {
    Self {
      inner: Box::new(inner),
      authentication: Authentication::default(),
    }
  }

  pub(crate) fn authentication(&self) -> Authentication {
    self.authentication.clone()
  }
}

impl tower::Service<Request> for Service {
  type Error = anyhow::Error;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>;
  type Response = Response;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request) -> Self::Future {
    self.inner.call(req)
  }
}

impl Clone for Service {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner.clone_boxed(),
      authentication: self.authentication.clone(),
    }
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
pub(crate) trait BuildService:
  Fn(SerializedArgs) -> Result<Service>
{
}

impl<F> BuildService for F where F: Fn(SerializedArgs) -> Result<Service>
{}

/// A layer that wraps a Service to produce another Service.
pub(crate) struct Layer {
  inner: Box<dyn tower::Layer<Service, Service = Service> + 'static>,
  verifier: Option<Arc<dyn CredentialVerifier>>,
}

impl Layer {
  pub(crate) fn new<L>(layer: L) -> Self
  where
    L: tower::Layer<Service, Service = Service> + 'static,
  {
    Self { inner: Box::new(layer), verifier: None }
  }

  pub(crate) fn with_authentication<L>(
    layer: L,
    verifier: Arc<dyn CredentialVerifier>,
  ) -> Self
  where
    L: tower::Layer<Service, Service = Service> + 'static,
  {
    Self { inner: Box::new(layer), verifier: Some(verifier) }
  }

  pub(crate) fn layer(&self, inner: Service) -> Service {
    let authentication = inner.authentication();
    let authentication = match &self.verifier {
      Some(verifier) => authentication.require(verifier.clone()),
      None => authentication,
    };
    let mut service = self.inner.layer(inner);
    service.authentication = authentication;
    service
  }
}

/// Factory trait for building layers.
pub(crate) trait BuildLayer:
  Fn(SerializedArgs) -> Result<Layer>
{
}
impl<F> BuildLayer for F where F: Fn(SerializedArgs) -> Result<Layer> {}
