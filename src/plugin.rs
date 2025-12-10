use std::collections::hash_map::HashMap;
use std::error::Error as StdError;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Frame, SizeHint};

/// A wrapper for Bytes based Body types like Full<Bytes>, Empty<Bytes>,
/// etc in crate http_body_util. Through this wrapper, different Body
/// implements can be converted into RequestBody and ResponseBody
/// handily.
pub struct BytesBufBodyWrapper<B, E> {
  inner: Pin<Box<dyn Body<Data = B, Error = E> + Send>>,
}

impl<B, E> BytesBufBodyWrapper<B, E> {
  pub fn new<T>(b: T) -> Self
  where
    T: Body<Data = B, Error = E> + Send + 'static,
    B: Buf,
    E: StdError + Send + Sync,
  {
    Self { inner: Box::pin(b) }
  }
}

impl<B, E> Body for BytesBufBodyWrapper<B, E>
where
  B: Buf,
  E: StdError + Send + Sync + 'static,
{
  type Data = B;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.inner.as_mut().poll_frame(cx).map_err(|e| e.into())
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

pub type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type Request = hyper::Request<RequestBody>;
pub type Response = hyper::Response<ResponseBody>;

/// To add clone function to the Service. The Clone trait can not be
/// added into the type definition of the Service directly, in rust only
/// the auto traits like Send, Sync etc can be added in to type
/// definitions.
trait CloneBoxedService: tower::Service<Request> {
  fn clone_boxed(
    &self,
  ) -> Box<
    dyn CloneBoxedService<
        Error = Self::Error,
        Response = Self::Response,
        Future = Pin<Box<dyn Future<Output = Result<Self::Response>>>>,
      > + Send,
  >;
}

impl<S> CloneBoxedService for S
where
  S: tower::Service<
      Request,
      Error = anyhow::Error,
      Response = Response,
      Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
    > + Clone
    + Send
    + 'static,
{
  fn clone_boxed(
    &self,
  ) -> Box<
    dyn CloneBoxedService<
        Error = anyhow::Error,
        Response = Response,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Send,
  > {
    Box::new(self.clone())
  }
}

/// The Service that plugins should be implemented. It is non-Sync and
/// clonable. Plugins should implement a tower Service and wrap it by
/// this struct.
pub struct Service {
  inner: Box<
    dyn CloneBoxedService<
        Error = anyhow::Error,
        Response = Response,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Send,
  >,
}

impl Service {
  pub fn new<S>(inner: S) -> Self
  where
    S: tower::Service<
        Request,
        Response = Response,
        Error = anyhow::Error,
        Future = Pin<Box<dyn Future<Output = Result<Response>>>>,
      > + Clone
      + Send
      + 'static,
  {
    Self { inner: Box::new(inner) }
  }
}

impl tower::Service<Request> for Service {
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

impl Clone for Service {
  fn clone(&self) -> Self {
    Self { inner: self.inner.clone_boxed() }
  }
}

impl std::fmt::Debug for Service {
  fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
    fmt.debug_struct("LocalService").finish()
  }
}

pub trait ListenerCloserTrait {
  fn shutdown(&self);
}

pub trait ListenerTrait {
  fn serve(self: Rc<Self>)
  -> Pin<Box<dyn Future<Output = Result<()>>>>;
}

pub type Listener = Box<dyn ListenerTrait>;
pub type ListenerCloser = Box<dyn ListenerCloserTrait>;

pub type SerializedArgs = serde_yaml::Value;

/// an alias for shorten complex trait definition.
pub trait ServiceFactory:
  Fn(SerializedArgs) -> Result<Service> + Sync + Send
{
}

impl<F> ServiceFactory for F where
  F: Fn(SerializedArgs) -> Result<Service> + Sync + Send
{
}

/// an alias for shorten complex trait definition.
pub trait ListenerFactory:
  Fn(SerializedArgs, Service) -> Result<(Listener, ListenerCloser)>
  + Sync
  + Send
{
}

impl<F> ListenerFactory for F where
  F: Fn(SerializedArgs, Service) -> Result<(Listener, ListenerCloser)>
    + Sync
    + Send
{
}

pub trait Plugin<'a> {
  fn name(&self) -> &'a str;

  fn listener_factories(
    &self,
  ) -> HashMap<&'a str, Box<dyn ListenerFactory>> {
    HashMap::new()
  }

  fn service_factories(
    &self,
  ) -> HashMap<&'a str, Box<dyn ServiceFactory>> {
    HashMap::new()
  }
}
