use std::collections::hash_map::HashMap;
use std::error::Error as StdError;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tower::util::BoxCloneService;

pub struct BytesBufBody<B, E> {
  inner: Pin<Box<dyn Body<Data = B, Error = E> + Send>>,
}

impl<B, E> BytesBufBody<B, E> {
  pub fn new<T>(b: T) -> Self
  where
    T: Body<Data = B, Error = E> + Send + 'static,
    B: Buf,
    E: Into<Box<dyn StdError + Send + Sync>>,
  {
    Self { inner: Box::pin(b) }
  }
}

impl<B, E> Body for BytesBufBody<B, E>
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
pub type Service = BoxCloneService<Request, Response, anyhow::Error>;
pub type Listener = Box<dyn ListenerTrait>;
pub type ListenerCloser = Box<dyn ListenerCloserTrait>;

pub trait ListenerCloserTrait {
  fn shutdown(&self);
}

pub trait ListenerTrait {
  fn serve(self: Rc<Self>)
  -> Pin<Box<dyn Future<Output = Result<()>>>>;
}

pub type SerializedArgs = serde_yaml::Value;

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

/// an alias for shorten complex trait definition.
pub trait ServiceFactory:
  Fn(SerializedArgs) -> Result<Service> + Sync + Send
{
}

impl<F> ServiceFactory for F where
  F: Fn(SerializedArgs) -> Result<Service> + Sync + Send
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
