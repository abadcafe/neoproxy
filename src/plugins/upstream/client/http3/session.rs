//! module: session
//! responsibility: open leased H3 streams using process-owned session
//! capacity public operations: SessionPool::{new,shared,open,close},
//! SessionLease data entities: SessionPool
//! tests: session_tests.rs, http3_tests.rs
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::establish::{self, Settings};
use super::io_progress::SendBuffer;
use super::lease::Session;
pub(in crate::plugins::upstream::client) use super::lease::SessionLease;
use super::sessions::{Bucket, Store};
use crate::context::RequestContext;
use crate::plugins::upstream::client::protocol::QuicConfig;
use crate::plugins::upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

pub(crate) struct SessionPool {
  settings: Settings,
  bucket: Arc<Bucket>,
  runtime: tokio::runtime::Handle,
  _store: Arc<Store>,
}
impl SessionPool {
  #[cfg(test)]
  pub(crate) fn new(
    address: std::net::SocketAddr,
    hostname: Option<String>,
    quic: QuicConfig,
    handshake_timeout: Duration,
    pool: crate::plugins::upstream::config::protocol::PoolConfig,
  ) -> Self {
    let runtime = tokio::runtime::Handle::current();
    Self::shared(
      address,
      hostname,
      quic,
      handshake_timeout,
      Store::new(1, pool.idle_timeout),
      runtime,
    )
  }

  pub(in crate::plugins::upstream::client) fn shared(
    address: std::net::SocketAddr,
    hostname: Option<String>,
    quic: QuicConfig,
    handshake_timeout: Duration,
    store: Arc<Store>,
    runtime: tokio::runtime::Handle,
  ) -> Self {
    Self {
      settings: Settings { address, hostname, quic, handshake_timeout },
      bucket: store.bucket(address, &runtime),
      runtime,
      _store: store,
    }
  }

  async fn checkout(
    &self,
    tls: &rustls::ClientConfig,
    ctx: Option<&RequestContext>,
  ) -> Result<SessionLease, UpstreamError> {
    self.bucket.retire();
    let permit = loop {
      let notified = self.bucket.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if self.bucket.is_closed() {
        return Err(UpstreamError::ProxyInternalError(
          "H3 pool closed".into(),
        ));
      }
      if let Some(permit) = self.bucket.reserve() {
        break permit;
      }
      if let Some(session) = self.bucket.select(&self.settings.hostname)
      {
        return Ok(session);
      }
      notified.await;
    };
    let settings = self.settings.clone();
    let tls = tls.clone();
    let (mut tx, rx) = tokio::sync::oneshot::channel();
    // Socket, timers and QUIC/H3 drivers are all created on the pool
    // runtime.
    let bucket = self.bucket.clone();
    self.runtime.spawn(async move {
      let observation =
        super::super::observation::ConnectionObservation::new();
      let reads = super::read_progress::Registry::default();
      let result = tokio::select! {
        _ = tx.closed() => { drop(permit); bucket.changed.notify_waiters(); return; }
        result = establish::establish(&settings, &tls, &observation, reads.clone()) => result,
      }.map(|(connection, sender)| {
        let session = Session::new(connection, sender, observation.clone(), reads, settings.hostname, permit);
        let lease = SessionLease::new(session.clone());
        bucket.insert(session);
        lease
      });
      // A cancelled receiver drops the lease, even when delivery won
      // the race with cancellation. Activity cannot leak in the cache.
      let _ = tx.send((result, observation));
      bucket.changed.notify_waiters();
    });
    let (result, observation) = rx.await.map_err(|_| {
      UpstreamError::ProxyInternalError("H3 connector stopped".into())
    })?;
    if result.is_err()
      && let Some(ctx) = ctx
    {
      observation.record(ctx);
    }
    result
  }

  pub(super) async fn open(
    &self,
    request: http::Request<()>,
    tls: &rustls::ClientConfig,
    _tracker: &Rc<StreamTracker>,
  ) -> Result<
    (
      h3::client::RequestStream<super::read_progress::Bidi, SendBuffer>,
      SessionLease,
      super::io_progress::Progress,
    ),
    UpstreamError,
  > {
    for attempt in 0..2 {
      let lease = self
        .checkout(tls, request.extensions().get::<RequestContext>())
        .await?;
      let session = lease.session();
      if let Some(ctx) = request.extensions().get::<RequestContext>() {
        session.observation.record(ctx);
      }
      let mut sender = session.sender.clone();
      super::super::retry_request::Progress::mark_request(&request);
      let settings = request
        .extensions()
        .get::<super::super::exchange_timeout::Timeouts>()
        .copied()
        .unwrap_or_default();
      match tokio::time::timeout(
        settings.send,
        sender.send_request(request.clone()),
      )
      .await
      .map_err(|_| {
        UpstreamError::ConnectionTimeout(
          "upstream send inactivity timeout".into(),
        )
      })? {
        Ok(stream) => {
          let progress = session.reads.get(stream.id());
          return Ok((stream, lease, progress));
        }
        Err(h3::error::StreamError::RemoteClosing) if attempt == 0 => {
          session.draining.store(true, Ordering::Release);
          drop(lease);
          self.bucket.retire();
        }
        Err(error) => {
          return Err(UpstreamError::ConnectionTerminated(
            error.to_string(),
          ));
        }
      }
    }
    unreachable!("second attempt returns")
  }

  pub(crate) fn close(&self) { /* Process-owned store closes after all workers drain. */
  }
}
