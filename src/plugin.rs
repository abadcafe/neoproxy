use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use tokio::sync;

/// Shutdown Handle for `Listener`s.
pub struct ShutdownHandle(Arc<sync::Notify>);

impl ShutdownHandle {
  pub fn new() -> Self {
    Self(Arc::new(sync::Notify::new()))
  }

  pub fn shutdown(&self) {
    self.0.notify_waiters()
  }

  pub async fn notified(&self) {
    self.0.notified().await
  }
}

impl Clone for ShutdownHandle {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

/// A wrapper for `Bytes` based `Body` types like `Full<Bytes>`,
/// `Empty<Bytes>`, etc in crate `http_body_util`. Through this wrapper,
/// different `Body` implements can be converted into `RequestBody` and
/// `ResponseBody` handily.
pub struct BytesBufBodyWrapper<B, E>(
  Pin<Box<dyn Body<Data = B, Error = E> + Send>>,
);

impl<B, E> BytesBufBodyWrapper<B, E> {
  pub fn new<T>(b: T) -> Self
  where
    T: Body<Data = B, Error = E> + Send + 'static,
    B: Buf,
    E: Error + Send + Sync,
  {
    Self(Box::pin(b))
  }
}

impl<B, E> Body for BytesBufBodyWrapper<B, E>
where
  B: Buf,
  E: Error + Send + Sync + 'static,
{
  type Data = B;
  type Error = anyhow::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.0.as_mut().poll_frame(cx).map_err(|e| e.into())
  }

  fn is_end_stream(&self) -> bool {
    self.0.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.0.size_hint()
  }
}

pub type RequestBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type ResponseBody = UnsyncBoxBody<Bytes, anyhow::Error>;
pub type Request = http::Request<RequestBody>;
pub type Response = http::Response<ResponseBody>;

/// To add `clone()` function to the `Service`. The `Clone` trait can
/// not be added into the type definition of the `Service` directly, in
/// rust only auto traits like `Send`, `Sync` etc can be added into type
/// definitions.
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

/// The `Service` that plugins should implement.
/// It is non-`Sync` and `Clone`. Plugins should implement a
/// `tower::Service` and wrap it in this struct.
/// Note: `Service` is a lightweight object that can be cloned and
/// created temporarily, even for each request.
pub struct Service(Box<dyn CloneService>);

impl Service {
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

pub trait Listening {
  fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>>;
  fn stop(&self);
}

pub struct Listener(Box<dyn Listening>);

impl Listener {
  pub fn new<L>(l: L) -> Self
  where
    L: Listening + 'static,
  {
    Self(Box::new(l))
  }

  pub fn start(&self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    self.0.start()
  }

  pub fn stop(&self) {
    self.0.stop()
  }
}

pub type SerializedArgs = serde_yaml::Value;

/// an alias for shorten complex trait definition.
pub trait BuildService: Fn(SerializedArgs) -> Result<Service> {}

impl<F> BuildService for F where F: Fn(SerializedArgs) -> Result<Service>
{}

pub struct ServiceBuilder(Box<dyn BuildService>);

impl ServiceBuilder {
  pub fn new<BS>(bs: BS) -> Self
  where
    BS: BuildService + 'static,
  {
    Self(Box::new(bs))
  }

  pub fn build(&self, args: SerializedArgs) -> Result<Service> {
    self.0(args)
  }
}

/// an alias for shorten complex trait definition.
pub trait BuildListener:
  Fn(SerializedArgs, Service) -> Result<Listener>
{
}

impl<F> BuildListener for F where
  F: Fn(SerializedArgs, Service) -> Result<Listener>
{
}

pub struct ListenerBuilder(Box<dyn BuildListener>);

impl ListenerBuilder {
  pub fn new<BL>(bl: BL) -> Self
  where
    BL: BuildListener + 'static,
  {
    Self(Box::new(bl))
  }

  pub fn build(
    &self,
    args: SerializedArgs,
    svc: Service,
  ) -> Result<Listener> {
    self.0(args, svc)
  }
}

pub trait Plugin {
  fn service_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn BuildService>> {
    None
  }

  fn listener_builder(
    &self,
    name: &str,
  ) -> Option<&Box<dyn BuildListener>> {
    None
  }

  fn finalize(&mut self) -> Pin<Box<dyn Future<Output = Result<()>>>> {
    Box::pin(async { Ok(()) })
  }
}

/// an alias for shorten complex trait definition.
pub trait BuildPlugin: Fn() -> Box<dyn Plugin> + Sync + Send {}

impl<F> BuildPlugin for F where F: Fn() -> Box<dyn Plugin> + Sync + Send {}

pub struct PluginBuilder(Box<dyn BuildPlugin>);

impl PluginBuilder {
  pub fn new<BP>(bl: BP) -> Self
  where
    BP: BuildPlugin + 'static,
  {
    Self(Box::new(bl))
  }

  pub fn build(&self) -> Box<dyn Plugin> {
    self.0()
  }
}
