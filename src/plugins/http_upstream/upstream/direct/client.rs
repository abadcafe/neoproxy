//! module: client
//! responsibility: select and pool authenticated origin transports
//! public operations: OriginClient::{new,send,close}
//! data entities: OriginClient, PoolKey, PoolEntry, Transport, Sender
//! tests: direct_tests.rs, test_origin_discovery.py

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::client::legacy::Client;
use tokio::time::Instant;

use super::super::forward::ForwardClient;
use super::super::http3::{self, SessionPool};
use super::super::origin_connector::OriginConnector;
use super::super::protocol::QuicConfig;
use super::alt_svc::AltServices;
use super::dns_https::DnsHttps;
use super::origin::{Origin, Route, WireProtocol};
use crate::http_message::{Request, RequestBody, Response};
use crate::plugins::http_upstream::config;
use crate::plugins::http_upstream::error::UpstreamError;
use crate::tracker::StreamTracker;

type HttpClient = Client<OriginConnector, RequestBody>;
#[derive(Clone, Eq, PartialEq, Hash)]
struct PoolKey {
  origin: Origin,
  route: Route,
  address: std::net::SocketAddr,
}
struct PoolEntry {
  transport: Rc<tokio::sync::OnceCell<Rc<Transport>>>,
  used: Instant,
}

impl PoolEntry {
  fn retained(&self, now: Instant, timeout: Duration) -> bool {
    Rc::strong_count(&self.transport) > 1
      || match self.transport.get().map(Rc::as_ref) {
        Some(Transport::Quic(session)) => !session.is_idle(timeout),
        _ => now.duration_since(self.used) < timeout,
      }
  }
}
enum Transport {
  Tcp(Box<HttpClient>),
  Quic(Box<SessionPool>),
}

pub(super) struct OriginClient {
  base: HttpClient,
  config: config::Upstream,
  tls: Arc<rustls::ClientConfig>,
  dns: DnsHttps,
  alternatives: RefCell<AltServices>,
  pools: RefCell<HashMap<PoolKey, PoolEntry>>,
  broken: RefCell<HashMap<(Origin, Route), Instant>>,
}

impl OriginClient {
  pub(super) fn new(
    config: &config::Upstream,
    tls: Arc<rustls::ClientConfig>,
  ) -> anyhow::Result<Self> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    Ok(Self {
      base: http_client(
        OriginConnector::new(config, tls.clone()),
        config,
      ),
      config: config.clone(),
      tls,
      dns: DnsHttps::new(
        config.dns_servers.as_deref(),
        config.dns_resolve_timeout,
      )?,
      alternatives: RefCell::new(AltServices::default()),
      pools: RefCell::new(HashMap::new()),
      broken: RefCell::new(HashMap::new()),
    })
  }

  pub(super) async fn send(
    &self,
    mut request: Request,
    tracker: &Rc<StreamTracker>,
  ) -> Result<Response, UpstreamError> {
    let ctx = request
      .extensions()
      .get::<crate::context::RequestContext>()
      .cloned();
    let origin = Origin::from_uri(request.uri()).ok_or_else(|| {
      UpstreamError::ProxyInternalError("invalid origin URI".into())
    })?;
    // Alt-Used describes this connection, never a previous proxy hop.
    request.headers_mut().remove("alt-used");
    // Optional discovery/probes share one budget. Once a request is
    // submitted, the caller's full response-header deadline applies;
    // cancelling a committed request must never trigger a replay.
    let selected = tokio::time::timeout(
      self.config.request_timeout / 3,
      self.discover_transport(
        &origin,
        request.uri(),
        tracker,
        ctx.as_ref(),
      ),
    )
    .await
    .ok()
    .flatten();
    let selected = if let Some((key, transport)) = selected {
      request.headers_mut().insert(
        "alt-used",
        key
          .route
          .authority()
          .parse()
          .expect("validated endpoint authority"),
      );
      Some((key, transport))
    } else if origin.is_https() && self.config.dns_servers.is_some() {
      // Custom discovery DNS also owns HTTPS authority address
      // resolution. This final path retains the request's remaining
      // budget and does not claim an alternative was used.
      let route = Route {
        host: origin.host().into(),
        port: origin.port(),
        protocol: WireProtocol::Negotiated,
      };
      Some(
        self
          .prepare_route(
            &origin,
            &route,
            request.uri(),
            tracker,
            ctx.as_ref(),
          )
          .await?,
      )
    } else {
      None
    };
    let response = if let Some((key, transport)) = selected {
      let response =
        self.exchange(&transport, request, tracker).await?;
      if response.status() == http::StatusCode::MISDIRECTED_REQUEST {
        self.alternatives.borrow_mut().invalidate(&origin);
        self.mark_broken(origin.clone(), key.route.clone());
        self.pools.borrow_mut().remove(&key);
      }
      response
    } else {
      self.base.send(request).await?
    };
    self.observe(&origin, &response);
    Ok(response)
  }

  async fn discover_transport(
    &self,
    origin: &Origin,
    uri: &http::Uri,
    tracker: &Rc<StreamTracker>,
    ctx: Option<&crate::context::RequestContext>,
  ) -> Option<(PoolKey, Rc<Transport>)> {
    let advertised =
      self.alternatives.borrow_mut().routes(origin, Instant::now());
    let routes = if advertised.is_empty() {
      self.dns.routes(origin).await
    } else {
      self.dns.alternatives(advertised).await
    };
    for route in routes {
      if self
        .broken
        .borrow()
        .get(&(origin.clone(), route.clone()))
        .is_some_and(|until| *until > Instant::now())
      {
        continue;
      }
      match self.prepare_route(origin, &route, uri, tracker, ctx).await
      {
        Ok(selected) => return Some(selected),
        Err(_) => {
          self.mark_broken(origin.clone(), route);
        }
      }
    }
    None
  }

  async fn prepare_route(
    &self,
    origin: &Origin,
    route: &Route,
    uri: &http::Uri,
    tracker: &Rc<StreamTracker>,
    ctx: Option<&crate::context::RequestContext>,
  ) -> Result<(PoolKey, Rc<Transport>), UpstreamError> {
    let started = std::time::Instant::now();
    let addresses = self.dns.addresses(route).await;
    if let Some(ctx) = ctx {
      let observation =
        super::super::observation::ConnectionObservation::new();
      observation.dns(
        &route.host,
        started.elapsed(),
        self.config.dns_resolve_timeout,
        &addresses,
      );
      observation.record(ctx);
    }
    crate::address_race::connect(
      addresses,
      self.config.request_timeout,
      |address| async move {
        let key = PoolKey {
          origin: origin.clone(),
          route: route.clone(),
          address,
        };
        self
          .transport(&key, uri, tracker)
          .await
          .map(|transport| (key, transport))
      },
    )
    .await
    .map_err(|error| match error {
      crate::address_race::RaceError::NoAddresses => {
        UpstreamError::DnsError(format!(
          "no addresses for {}",
          route.host
        ))
      }
      crate::address_race::RaceError::InvalidDeadline => {
        UpstreamError::ProxyInternalError(
          "origin deadline exceeds clock range".into(),
        )
      }
      crate::address_race::RaceError::Timeout => {
        UpstreamError::ConnectionTimeout(
          "origin connection deadline exceeded".into(),
        )
      }
      crate::address_race::RaceError::Failed(error) => error,
    })
  }

  async fn exchange(
    &self,
    transport: &Transport,
    request: Request,
    tracker: &Rc<StreamTracker>,
  ) -> Result<Response, UpstreamError> {
    match transport {
      Transport::Tcp(client) => client.send(request).await,
      Transport::Quic(session) => {
        let (mut parts, body) = request.into_parts();
        parts.version = http::Version::HTTP_3;
        http3::exchange(
          session,
          &self.tls,
          http::Request::from_parts(parts, ()),
          body,
          tracker,
        )
        .await
      }
    }
  }

  fn mark_broken(&self, origin: Origin, route: Route) {
    let mut broken = self.broken.borrow_mut();
    broken.retain(|_, until| *until > Instant::now());
    if broken.len() >= 1024
      && !broken.contains_key(&(origin.clone(), route.clone()))
      && let Some(oldest) = broken
        .iter()
        .min_by_key(|(_, until)| **until)
        .map(|(key, _)| key.clone())
    {
      broken.remove(&oldest);
    }
    broken.insert(
      (origin, route),
      Instant::now() + Duration::from_secs(30),
    );
  }

  fn observe(&self, origin: &Origin, response: &Response) {
    if response.status() != http::StatusCode::MISDIRECTED_REQUEST {
      self.alternatives.borrow_mut().observe(
        origin,
        response.headers(),
        Instant::now(),
      );
    }
  }

  async fn transport(
    &self,
    key: &PoolKey,
    uri: &http::Uri,
    tracker: &Rc<StreamTracker>,
  ) -> Result<Rc<Transport>, UpstreamError> {
    let now = Instant::now();
    let slot = if self.config.pool_config.max_idle_per_host == 0 {
      Rc::new(tokio::sync::OnceCell::new())
    } else {
      let mut pools = self.pools.borrow_mut();
      let timeout = self.config.pool_config.idle_timeout;
      // A hot pooled connection needs only its own activity check.
      // Scan other origins only when a missing/expired key is admitted.
      if pools
        .get(key)
        .is_none_or(|entry| !entry.retained(now, timeout))
      {
        pools.retain(|_, entry| entry.retained(now, timeout));
        if pools.len() >= 1024
          && !pools.contains_key(key)
          && let Some(oldest) = pools
            .iter()
            .min_by_key(|(_, entry)| entry.used)
            .map(|(key, _)| key.clone())
        {
          pools.remove(&oldest);
        }
      }
      let entry =
        pools.entry(key.clone()).or_insert_with(|| PoolEntry {
          transport: Rc::new(tokio::sync::OnceCell::new()),
          used: now,
        });
      entry.used = now;
      entry.transport.clone()
    };
    let transport = slot
      .get_or_try_init(|| self.build_transport(key, uri))
      .await?
      .clone();
    // Reconnect a stale session before committing a new request, so a
    // failed handshake can still fall back without replaying a body.
    if let Transport::Quic(session) = transport.as_ref() {
      session.prepare(&self.tls, tracker).await?;
    }
    Ok(transport)
  }

  async fn build_transport(
    &self,
    key: &PoolKey,
    uri: &http::Uri,
  ) -> Result<Rc<Transport>, UpstreamError> {
    let transport = if key.route.protocol == WireProtocol::Http3 {
      let quic = &self.config.quic;
      let session = SessionPool::new(
        key.address.to_string(),
        Some(key.origin.host().into()),
        QuicConfig {
          max_idle_timeout: quic.max_idle_timeout,
          keep_alive_interval: quic.keep_alive_interval,
          max_concurrent_bidi_streams: quic.max_concurrent_bidi_streams,
          initial_mtu: quic.initial_mtu,
          send_window: quic.send_window,
          receive_window: quic.receive_window,
        },
        self
          .config
          .http3_handshake_timeout
          .min(self.config.request_timeout / 3)
          .min(Duration::from_secs(1)),
        self.config.dns_resolve_timeout,
        self.config.pool_config.clone(),
      );
      Transport::Quic(Box::new(session))
    } else {
      let mut tls = (*self.tls).clone();
      let expected = match key.route.protocol {
        WireProtocol::Http2 => {
          tls.alpn_protocols = vec![b"h2".to_vec()];
          Some(b"h2".as_slice())
        }
        WireProtocol::Http1 => {
          tls.alpn_protocols = vec![b"http/1.1".to_vec()];
          Some(b"http/1.1".as_slice())
        }
        _ => None,
      };
      let endpoint = format!("https://{}/", key.address)
        .parse()
        .expect("numeric origin endpoint");
      let mut connector =
        OriginConnector::new(&self.config, Arc::new(tls))
          .routed(endpoint, expected);
      connector.prepare(uri.clone()).await.map_err(|error| {
        crate::plugins::http_upstream::error::classify_connect_error(
          error.into(),
        )
      })?;
      Transport::Tcp(Box::new(http_client(connector, &self.config)))
    };
    Ok(Rc::new(transport))
  }

  pub(super) fn close(&self) {
    for entry in self.pools.borrow().values() {
      if let Some(transport) = entry.transport.get()
        && let Transport::Quic(session) = transport.as_ref()
      {
        session.close();
      }
    }
    self.pools.borrow_mut().clear();
  }
}

fn http_client(
  connector: OriginConnector,
  config: &config::Upstream,
) -> HttpClient {
  Client::builder(hyper_util::rt::TokioExecutor::new())
    .pool_timer(hyper_util::rt::TokioTimer::new())
    .pool_max_idle_per_host(config.pool_config.max_idle_per_host)
    .pool_idle_timeout(config.pool_config.idle_timeout)
    .build(connector)
}

pub(super) struct Sender<'a> {
  pub(super) client: &'a OriginClient,
  pub(super) tracker: &'a Rc<StreamTracker>,
}
impl ForwardClient for Sender<'_> {
  async fn send(
    &self,
    request: Request,
  ) -> Result<Response, UpstreamError> {
    self.client.send(request, self.tracker).await
  }
}
