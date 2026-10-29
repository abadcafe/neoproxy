//! module: http_pool
//! responsibility: lease complete HTTP/1 connections to the calling
//! worker public operations: ProxyPool::{new,shared,connect,close},
//! ForwardClient data entities: ProxyPool, PooledBody
//! tests: HTTP pool process contracts
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};
#[cfg(test)]
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use tower::{Service, ServiceExt};

use super::exchange_timeout::{Control, TimedIo, Timeouts, UploadBody};
use super::forward::ForwardClient;
use super::http_cache::{Cache, Connection, Key};
use super::observation::ConnectionObservation;
use super::transport_io::ProxyIo;
use crate::context::RequestContext;
use crate::http_message::{
  BytesBufBodyWrapper, Request, RequestBody, Response, ResponseBody,
};
use crate::plugins::upstream::error::{
  UpstreamError, classify_http_client_error,
};
use crate::tracker::StreamTracker;

#[derive(Clone)]
pub(super) struct ProxyPool<C> {
  connector: C,
  cache: Arc<Cache>,
  key: Option<Key>,
  tracker: Rc<StreamTracker>,
}
impl<C> ProxyPool<C> {
  #[cfg(test)]
  pub(super) fn new(
    connector: C,
    max_idle: usize,
    idle_timeout: Duration,
    tracker: Rc<StreamTracker>,
  ) -> Self {
    Self {
      connector,
      cache: Cache::new(
        max_idle,
        idle_timeout,
        crate::header_limits::ResponseLimits::default().limits(),
      ),
      key: None,
      tracker,
    }
  }

  pub(super) fn shared(
    connector: C,
    cache: Arc<Cache>,
    key: Key,
    tracker: Rc<StreamTracker>,
  ) -> Self {
    Self { connector, cache, key: Some(key), tracker }
  }

  pub(super) fn proxy_authority(&self) -> Option<String> {
    self.key.as_ref().map(|key| match &key.server_name {
      Some(host) => format!(
        "{}:{}",
        if host.contains(':') {
          format!("[{host}]")
        } else {
          host.clone()
        },
        key.endpoint.port()
      ),
      None => key.endpoint.to_string(),
    })
  }

  pub(super) fn builder(&self) -> http1::Builder {
    let mut builder = http1::Builder::new();
    if self.cache.limits.count() != 100 {
      builder.max_headers(self.cache.limits.count());
    }
    builder
      .max_header_size(self.cache.limits.bytes() as usize)
      .max_buf_size(
        (self.cache.limits.bytes() as usize).max(8192 + 4096 * 100),
      );
    builder
  }

  pub(super) fn close(&self) { /* Shared pools outlive individual upstreams. */
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
  ) -> Result<Connection, UpstreamError> {
    let io = self.connect(uri, ctx).await?;
    let observation = io.observation();
    let timeout = Control::default();
    let (sender, connection) = self
      .builder()
      .handshake(TimedIo::new(io, timeout.clone()))
      .await
      .map_err(|error| classify_http_client_error(error.into()))?;
    Ok(Connection {
      sender,
      driver: Box::pin(connection),
      observation,
      timeout,
    })
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
    let settings = request
      .extensions()
      .get::<Timeouts>()
      .copied()
      .unwrap_or_default();
    let ctx = request.extensions().get::<RequestContext>().cloned();
    let uri = request.uri().clone();
    let key = self.key.clone().unwrap_or(Key {
      endpoint: "127.0.0.1:0".parse().expect("literal address"),
      server_name: None,
      origin: None,
    });
    let cached = self.cache.take(&key);
    let mut reused = cached.is_some();
    let mut connection = match cached {
      Some(connection) => connection,
      None => self.open(uri.clone(), ctx.as_ref()).await?,
    };
    if let Some(ctx) = &ctx {
      connection.observation.record(ctx);
    }
    if key.origin.is_some() {
      *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
        .parse()
        .expect("validated origin path");
    }
    let mut driver_done = false;
    let response = loop {
      let readiness = {
        let ready = connection.sender.ready();
        tokio::pin!(ready);
        tokio::select! {
          biased;
          result = &mut connection.driver => Err(match result { Err(error) => classify_http_client_error(error.into()), Ok(()) => UpstreamError::ConnectionTerminated("HTTP connection closed".into()) }),
          result = &mut ready => result.map_err(|error| classify_http_client_error(error.into())),
        }
      };
      if let Err(error) = readiness {
        if !reused {
          return Err(error);
        }
        reused = false;
        connection = self.open(uri.clone(), ctx.as_ref()).await?;
        if let Some(ctx) = &ctx {
          connection.observation.record(ctx);
        }
        continue;
      }
      connection.timeout.start(settings);
      request = request
        .map(|body| UploadBody::wrap(body, connection.timeout.clone()));
      super::retry_request::Progress::mark_request(&request);
      let result = {
        let pending = connection.sender.try_send_request(request);
        tokio::pin!(pending);
        tokio::select! {
          result = &mut pending => result,
          _ = &mut connection.driver => { driver_done = true; pending.await }
        }
      };
      match result {
        Ok(response) => break response,
        Err(mut error) => {
          // Hyper returns the request only when it has not been sent.
          // Never retry an exchange whose bytes may have reached the
          // peer.
          if let Some(unsent) = error.take_message() {
            super::retry_request::Progress::unsent(&unsent);
            if !reused {
              return Err(classify_http_client_error(
                error.into_error().into(),
              ));
            }
            request = unsent;
            reused = false;
            driver_done = false;
            connection = self.open(uri.clone(), ctx.as_ref()).await?;
            if let Some(ctx) = &ctx {
              connection.observation.record(ctx);
            }
            continue;
          }
          return Err(classify_http_client_error(
            error.into_error().into(),
          ));
        }
      }
    };
    connection.timeout.response_started();
    let (mut parts, inner) = response.into_parts();
    parts.extensions.insert(connection.observation.clone());
    if driver_done {
      return Ok(Response::from_parts(
        parts,
        ResponseBody::new(BytesBufBodyWrapper::new(inner)),
      ));
    }
    let (recycle, completed) =
      tokio::sync::oneshot::channel::<SendRequest<RequestBody>>();
    let (released, release) = tokio::sync::oneshot::channel();
    let Connection { sender, mut driver, observation, timeout } =
      connection;
    let response_timeout = timeout.clone();
    let cache = self.cache.clone();
    // The driver belongs to this lease. Cancellation drops it instead
    // of returning a partially exchanged connection to the global pool.
    self.tracker.register_connection(async move {
      let mut sender = tokio::select! {
        _ = &mut driver => return,
        result = completed => match result { Ok(sender) => sender, Err(_) => return },
      };
      tokio::select! {
        _ = &mut driver => return,
        result = sender.ready() => { if result.is_err() { return; } }
      }
      timeout.disable();
      cache.put(key, Connection { sender, driver, observation, timeout });
      let _ = released.send(());
    });
    let mut body = PooledBody {
      timeout: response_timeout,
      inner,
      sender: Some(sender),
      recycle: Some(recycle),
      release: Some(release),
      final_frame: None,
    };
    if body.inner.is_end_stream() {
      body.recycle();
      if let Some(release) = body.release.take() {
        let _ = release.await;
      }
    }
    Ok(Response::from_parts(
      parts,
      ResponseBody::new(BytesBufBodyWrapper::new(body)),
    ))
  }
}
struct PooledBody {
  release: Option<tokio::sync::oneshot::Receiver<()>>,
  final_frame: Option<Frame<Bytes>>,
  timeout: Control,
  inner: hyper::body::Incoming,
  sender: Option<SendRequest<RequestBody>>,
  recycle:
    Option<tokio::sync::oneshot::Sender<SendRequest<RequestBody>>>,
}

impl PooledBody {
  // Publish the lease before exposing its final bytes. Otherwise
  // another worker can open a redundant connection after the client
  // consumes EOF but before the recycling task runs. A closed driver
  // simply drops ACK.
  fn poll_released(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
    if let Some(release) = &mut self.release {
      std::task::ready!(Pin::new(release).poll(cx)).ok();
      self.release = None;
    }
    Poll::Ready(self.final_frame.take().map(Ok))
  }

  fn recycle(&mut self) {
    if self.sender.is_none() {
      return;
    }
    // An early response must not wait for an unfinished upload. Such a
    // connection cannot become reusable until that upload is resolved.
    if !self.timeout.upload_flushed() {
      self.release = None;
    }
    self.timeout.response_complete();
    if let Some(sender) = self.sender.take() {
      let _ = self
        .recycle
        .take()
        .expect("body completion has a recycler")
        .send(sender);
    }
  }
}

impl Body for PooledBody {
  type Data = Bytes;
  type Error = hyper::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
    if self.sender.is_none() && self.recycle.is_none() {
      return self.poll_released(cx);
    }
    let result = Pin::new(&mut self.inner).poll_frame(cx);
    if matches!(result, Poll::Ready(Some(Err(_)))) {
      self.sender = None;
      self.recycle = None;
      self.release = None;
    } else if result.is_ready() && self.inner.is_end_stream() {
      self.recycle();
      if let Poll::Ready(Some(Ok(frame))) = result {
        self.final_frame = Some(frame);
      }
      return self.poll_released(cx);
    }
    result
  }

  fn is_end_stream(&self) -> bool {
    self.inner.is_end_stream()
      && self.release.is_none()
      && self.final_frame.is_none()
  }

  fn size_hint(&self) -> SizeHint {
    if let Some(data) =
      self.final_frame.as_ref().and_then(Frame::data_ref)
    {
      return SizeHint::with_exact(data.len() as u64);
    }
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
