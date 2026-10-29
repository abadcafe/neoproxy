//! module: egress
//! responsibility: carry authorized requests through a dynamic SOCKS5
//! egress hop public operations: Egress::{new,connect,forward}
//! data entities: Connector, Egress
//! tests: test_e2b_policy.py
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use tower::Service;

use super::ConnectionPools;
use super::http::connector::{ProxyConnector, TlsProxyConnector};
use super::http::transport::ProxyTransport;
use super::protocol::ConnectResult;
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::upstream::config;
use crate::plugins::upstream::egress::Proxy;
use crate::plugins::upstream::error::{
  UpstreamError, classify_http_client_error,
};
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget, parse_connect_target,
};
use crate::stream::Io;
use crate::task_tracker::TaskTracker;

#[derive(Clone)]
struct Connector {
  config: config::Upstream,
  proxy: Arc<Proxy>,
  endpoints: Vec<SocketAddr>,
  target: ConnectTarget,
  origin_tls: Arc<rustls::ClientConfig>,
  ctx: Option<RequestContext>,
}
impl Connector {
  async fn open(
    &self,
  ) -> Result<
    (Box<dyn Io>, super::observation::ConnectionObservation),
    UpstreamError,
  > {
    let options = crate::tcp_options::TcpOptions {
      time: self.config.tcp_keep_alive_time,
      interval: self.config.tcp_keep_alive_interval,
      retries: self.config.tcp_keep_alive_retries,
    };
    let mut last = None;
    for endpoint in &self.endpoints {
      let plain =
        ProxyConnector::new(*endpoint, self.config.connect_timeout)
          .with_tcp_options(options);
      let result = match &self.proxy.tls {
        Some(tls) => TlsProxyConnector::new(
          plain,
          tls.config.clone(),
          tls.server_name.clone(),
          self.config.tls_handshake_timeout,
        )
        .call(self.target.uri())
        .await
        .map(|io| {
          let (io, obs) = io.into_parts();
          (Box::new(io) as Box<dyn Io>, obs)
        }),
        None => plain.clone().call(self.target.uri()).await.map(|io| {
          let (io, obs) = io.into_parts();
          (Box::new(io) as Box<dyn Io>, obs)
        }),
      };
      match result {
        Ok((io, observation)) => {
          if let Some(ctx) = &self.ctx {
            observation.record(ctx);
          }
          let control = super::exchange_timeout::Control::default();
          control.start(super::exchange_timeout::Timeouts {
            read: self.config.upstream_read_timeout,
            send: self.config.upstream_send_timeout,
          });
          control.response_started();
          let mut io =
            TokioIo::new(super::exchange_timeout::TimedIo::new(
              TokioIo::new(io),
              control.clone(),
            ));
          super::socks5::handshake::negotiate(
            &mut io,
            &self.target,
            self.proxy.user.as_ref(),
          )
          .await?;
          control.disable();
          return Ok((Box::new(io), observation));
        }
        Err(error) => {
          if let Some(ctx) = &self.ctx {
            super::observation::ConnectionObservation::record_error(
              &error, ctx,
            );
          }
          last = Some(classify_http_client_error(error.into()))
        }
      }
    }
    Err(last.unwrap_or_else(|| {
      UpstreamError::DestinationUnavailable(
        "no egress proxy addresses".into(),
      )
    }))
  }
}
impl Service<http::Uri> for Connector {
  type Error = std::io::Error;
  type Future = Pin<
    Box<
      dyn Future<Output = Result<Self::Response, Self::Error>> + Send,
    >,
  >;
  type Response = ProxyTransport<Box<dyn Io>>;

  fn poll_ready(
    &mut self,
    _: &mut Context<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, uri: http::Uri) -> Self::Future {
    let connector = self.clone();
    Box::pin(async move {
      let (mut io, observation) =
        connector.open().await.map_err(std::io::Error::other)?;
      if uri.scheme_str() == Some("https") {
        let host = uri
          .host()
          .expect("validated origin")
          .trim_start_matches('[')
          .trim_end_matches(']');
        let name =
          rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(std::io::Error::other)?;
        let pending =
          tokio_rustls::TlsConnector::from(connector.origin_tls)
            .connect(name, io);
        io = Box::new(
          tokio::time::timeout(
            connector.config.tls_handshake_timeout,
            pending,
          )
          .await
          .map_err(|_| {
            std::io::Error::new(
              std::io::ErrorKind::TimedOut,
              "origin TLS handshake timed out",
            )
          })??,
        );
      }
      Ok(ProxyTransport::new(io, observation))
    })
  }
}
async fn connector(
  config: &config::Upstream,
  pools: &Arc<ConnectionPools>,
  proxy: Arc<Proxy>,
  remote_dns: bool,
  permitted: Vec<SocketAddr>,
  target: &ConnectTarget,
  ctx: Option<&RequestContext>,
) -> Result<Connector, UpstreamError> {
  let pool = pools.get(&config.use_connection_pool);
  let endpoints = pool.dns.resolve(&proxy.address, ctx).await?;
  let target = if remote_dns {
    target.clone()
  } else {
    let parts = http::Request::builder()
      .method("CONNECT")
      .uri(permitted[0].to_string())
      .body(())
      .expect("authorized address")
      .into_parts()
      .0;
    parse_connect_target(&parts).expect("authorized CONNECT target")
  };
  Ok(Connector {
    config: config.clone(),
    proxy,
    endpoints,
    target,
    origin_tls: pool.tls.clone(),
    ctx: ctx.cloned(),
  })
}
pub(super) struct Egress<'a> {
  config: &'a config::Upstream,
  pools: &'a Arc<ConnectionPools>,
  proxy: Arc<Proxy>,
  remote_dns: bool,
  permitted: Vec<SocketAddr>,
}
impl<'a> Egress<'a> {
  pub(super) fn new(
    config: &'a config::Upstream,
    pools: &'a Arc<ConnectionPools>,
    route: &crate::plugins::upstream::egress::Route,
    permitted: Vec<SocketAddr>,
  ) -> Self {
    Self {
      config,
      pools,
      proxy: route.proxy().expect("proxy route").clone(),
      remote_dns: route.remote_dns(),
      permitted,
    }
  }

  pub(super) async fn connect(
    self,
    target: &ConnectTarget,
    ctx: Option<&RequestContext>,
  ) -> Result<ConnectResult, UpstreamError> {
    if let Some(ctx) = ctx {
      ctx.set(
        crate::context::fields::upstream::PROTOCOL,
        Arc::from("socks5"),
      );
    }
    let connector = connector(
      self.config,
      self.pools,
      self.proxy,
      self.remote_dns,
      self.permitted,
      target,
      ctx,
    )
    .await?;
    let (transport, observation) = connector.open().await?;
    if let Some(ctx) = ctx {
      observation.record(ctx);
      ctx.set(
        crate::context::fields::upstream::PROTOCOL,
        Arc::from("socks5"),
      );
    }
    Ok(ConnectResult {
      transport,
      upstream_addr: observation.peer(),
      upstream_response: None,
      tunnel_idle_timeout: self.config.tunnel_idle_timeout,
    })
  }

  pub(super) async fn forward(
    self,
    target: &ForwardTarget,
    mut parts: http::request::Parts,
    body: RequestBody,
    ctx: &RequestContext,
    tracker: &std::sync::Arc<TaskTracker>,
  ) -> Result<Response, UpstreamError> {
    ctx.set(
      crate::context::fields::upstream::PROTOCOL,
      Arc::from("socks5"),
    );
    let authority =
      target.absolute_uri().authority().expect("validated origin");
    let port = authority.port_u16().unwrap_or(
      if target.absolute_uri().scheme_str() == Some("https") {
        443
      } else {
        80
      },
    );
    let connect_parts = http::Request::builder()
      .method("CONNECT")
      .uri(format!("{}:{port}", authority.host()))
      .body(())
      .expect("validated origin")
      .into_parts()
      .0;
    let connect_target = parse_connect_target(&connect_parts)
      .expect("validated origin CONNECT");
    let endpoint = self.permitted[0];
    let connector = connector(
      self.config,
      self.pools,
      self.proxy,
      self.remote_dns,
      self.permitted,
      &connect_target,
      Some(ctx),
    )
    .await?;
    ctx.set(
      crate::context::fields::upstream::PROTOCOL,
      Arc::from("socks5"),
    );
    parts.extensions.insert(super::exchange_timeout::Timeouts {
      read: self.config.upstream_read_timeout,
      send: self.config.upstream_send_timeout,
    });
    let pool = super::http_pool::ProxyPool::shared(
      connector,
      super::http_cache::Cache::new(
        0,
        std::time::Duration::from_secs(60),
        self.pools.get(&self.config.use_connection_pool).http.limits,
        std::sync::Arc::new(TaskTracker::new()),
        tokio::runtime::Handle::current(),
      ),
      super::http_cache::Key {
        endpoint,
        server_name: None,
        origin: Some(authority.to_string()),
      },
      tracker.clone(),
    );
    super::forward::forward_request(
      pool, &None, target, parts, body, ctx,
    )
    .await
  }
}
