//! module: http_pool
//! responsibility: reuse HTTP/1 connections to one configured proxy
//! public operations: ProxyPool::{new, close}, ForwardClient
//! data entities: ProxyPool, PoolState, IdleSender, PooledBody
//! tests: test_pool_expiry.py, test_upstream_http_proxy.py

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tower::{Service, ServiceExt};

use super::forward::ForwardClient;
use super::http::ProxyIo;
use super::observation::ConnectionObservation;
use crate::context::RequestContext;
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response, ResponseBody,
};
use crate::plugins::upstream::error::{
  UpstreamError, classify_http_client_error,
};
use crate::tracker::StreamTracker;

struct PooledSender {
  sender: SendRequest<RequestBody>,
  observation: ConnectionObservation,
}
impl std::ops::Deref for PooledSender {
  type Target = SendRequest<RequestBody>;

  fn deref(&self) -> &Self::Target {
    &self.sender
  }
}
impl std::ops::DerefMut for PooledSender {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.sender
  }
}

struct IdleSender {
  sender: PooledSender,
  expires: Instant,
}

struct PoolState {
  idle: Vec<IdleSender>,
  reaper: Option<AbortHandle>,
  max_idle: usize,
  idle_timeout: Duration,
  stopped: bool,
}

impl Drop for PoolState {
  fn drop(&mut self) {
    if let Some(reaper) = self.reaper.take() {
      reaper.abort();
    }
  }
}

pub(super) struct ProxyPool<C> {
  connector: C,
  state: Rc<RefCell<PoolState>>,
  tracker: Rc<StreamTracker>,
}

impl<C: Clone> Clone for ProxyPool<C> {
  fn clone(&self) -> Self {
    Self {
      connector: self.connector.clone(),
      state: self.state.clone(),
      tracker: self.tracker.clone(),
    }
  }
}

impl<C> ProxyPool<C> {
  pub(super) fn new(
    connector: C,
    max_idle: usize,
    idle_timeout: Duration,
    tracker: Rc<StreamTracker>,
  ) -> Self {
    Self {
      connector,
      state: Rc::new(RefCell::new(PoolState {
        idle: Vec::new(),
        reaper: None,
        max_idle,
        idle_timeout,
        stopped: false,
      })),
      tracker,
    }
  }

  pub(super) fn close(&self) {
    let mut state = self.state.borrow_mut();
    state.stopped = true;
    state.idle.clear();
    if let Some(reaper) = state.reaper.take() {
      reaper.abort();
    }
  }

  fn checkout(&self) -> Option<PooledSender> {
    let mut state = self.state.borrow_mut();
    while let Some(entry) = state.idle.pop() {
      if entry.expires > Instant::now() && entry.sender.is_ready() {
        return Some(entry.sender);
      }
    }
    None
  }
}

impl<C> ProxyPool<C>
where
  C: Service<http::Uri, Error = std::io::Error> + Clone,
  C::Response: ProxyIo,
{
  pub(super) async fn connect(
    &self,
    uri: http::Uri,
    ctx: Option<&RequestContext>,
  ) -> Result<C::Response, UpstreamError> {
    if self.state.borrow().stopped {
      return Err(UpstreamError::ProxyInternalError(
        "proxy pool stopped".into(),
      ));
    }
    let result = self.connector.clone().oneshot(uri).await;
    if let (Err(error), Some(ctx)) = (&result, ctx) {
      ConnectionObservation::record_error(error, ctx);
    }
    result.map_err(|error| classify_http_client_error(error.into()))
  }

  async fn open(
    &self,
    uri: http::Uri,
    ctx: Option<&RequestContext>,
  ) -> Result<PooledSender, UpstreamError> {
    let io = self.connect(uri, ctx).await?;
    let observation = io.observation();
    let (mut sender, connection) =
      http1::handshake(io).await.map_err(|error| {
        if let Some(ctx) = ctx {
          observation.record(ctx);
        }
        classify_http_client_error(error.into())
      })?;
    self.tracker.register_connection(async move {
      if let Err(error) = connection.await {
        tracing::debug!("upstream HTTP connection ended: {error}");
      }
    });
    sender.ready().await.map_err(|error| {
      if let Some(ctx) = ctx {
        observation.record(ctx);
      }
      classify_http_client_error(error.into())
    })?;
    Ok(PooledSender { sender, observation })
  }
}

impl<C> ForwardClient for ProxyPool<C>
where
  C: Service<http::Uri, Error = std::io::Error> + Clone,
  C::Response: ProxyIo,
{
  async fn send(
    &self,
    mut request: Request,
  ) -> Result<Response, UpstreamError> {
    super::http1_framing::prepare_request(&mut request);
    let ctx = request.extensions().get::<RequestContext>().cloned();
    let uri = request.uri().clone();
    let cached = self.checkout();
    let reused = cached.is_some();
    let mut sender = match cached {
      Some(sender) => sender,
      None => self.open(uri.clone(), ctx.as_ref()).await?,
    };
    if let Some(ctx) = &ctx {
      sender.observation.record(ctx);
    }
    super::retry_request::Progress::mark_request(&request);
    let response = match sender.try_send_request(request).await {
      Ok(response) => response,
      Err(mut error) => {
        // Retry only when Hyper returns the unsent message. Never
        // replay a body/method whose bytes may have reached the peer.
        if reused && let Some(request) = error.take_message() {
          sender = self.open(uri, ctx.as_ref()).await?;
          if let Some(ctx) = &ctx {
            sender.observation.record(ctx);
          }
          sender
            .send_request(request)
            .await
            .map_err(|error| classify_http_client_error(error.into()))?
        } else {
          return Err(classify_http_client_error(
            error.into_error().into(),
          ));
        }
      }
    };
    let (mut parts, inner) = response.into_parts();
    parts.extensions.insert(sender.observation.clone());
    let (recycle, completed) = tokio::sync::oneshot::channel();
    return_when_complete(
      completed,
      Rc::downgrade(&self.state),
      self.tracker.clone(),
    );
    let mut body = PooledBody {
      inner,
      sender: Some(sender),
      recycle: Some(recycle),
    };
    if body.inner.is_end_stream() {
      body.recycle();
    }
    Ok(Response::from_parts(
      parts,
      ResponseBody::new(BytesBufBodyWrapper::new(body)),
    ))
  }
}

struct PooledBody {
  inner: hyper::body::Incoming,
  sender: Option<PooledSender>,
  recycle: Option<tokio::sync::oneshot::Sender<PooledSender>>,
}

impl PooledBody {
  fn recycle(&mut self) {
    if let Some(sender) = self.sender.take() {
      let _ = self
        .recycle
        .take()
        .expect("body completion has a recycler")
        .send(sender);
    }
  }
}

fn return_when_complete(
  completed: tokio::sync::oneshot::Receiver<PooledSender>,
  state: Weak<RefCell<PoolState>>,
  tracker: Rc<StreamTracker>,
) {
  let shutdown = tracker.shutdown_handle();
  let recycling_tracker = tracker.clone();
  // ResponseBody is Send; the oneshot transfers the completed sender
  // back into its owning worker without exposing worker-local state.
  tracker.register_connection(async move {
    let mut sender = tokio::select! {
      _ = shutdown.notified() => return,
      sender = completed => match sender { Ok(sender) => sender, Err(_) => return },
    };
    tokio::select! {
      _ = shutdown.notified() => return,
      ready = sender.ready() => { if ready.is_err() { return; } }
    }
    let Some(shared) = state.upgrade() else { return; };
    let mut pool = shared.borrow_mut();
    if pool.stopped || pool.idle.len() >= pool.max_idle { return; }
    let expires = Instant::now() + pool.idle_timeout;
    pool.idle.push(IdleSender { sender, expires });
    if pool.reaper.is_none() {
      pool.reaper = Some(recycling_tracker.register_connection(async move {
        loop {
          let deadline = {
            let Some(shared) = state.upgrade() else { return; };
            let mut pool = shared.borrow_mut();
            pool.idle.retain(|entry| entry.expires > Instant::now() && !entry.sender.is_closed());
            let Some(deadline) = pool.idle.iter().map(|entry| entry.expires).min() else { pool.reaper = None; return; };
            deadline
          };
          tokio::select! {
            _ = shutdown.notified() => return,
            _ = tokio::time::sleep_until(deadline) => {}
          }
        }
      }));
    }
  });
}

impl Body for PooledBody {
  type Data = Bytes;
  type Error = hyper::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
    let result = Pin::new(&mut self.inner).poll_frame(cx);
    if matches!(result, Poll::Ready(Some(Err(_)))) {
      self.sender = None;
    } else if result.is_ready() && self.inner.is_end_stream() {
      self.recycle();
    }
    result
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

impl Drop for PooledBody {
  fn drop(&mut self) {
    if self.inner.is_end_stream() {
      self.recycle();
    }
  }
}
