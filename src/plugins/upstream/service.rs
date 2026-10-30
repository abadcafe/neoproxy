//! module: plugins::upstream::service
//! responsibility: dispatch validated requests to upstream
//! transports
//! public operations: UpstreamService, build
//! data entities: UpstreamService
//! tests: service_tests.rs

use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use tracing::warn;

use super::client::UpstreamRegistry;
use super::client::protocol::ConnectResult;
use super::error::UpstreamError;
use super::target_parser::{
  self, ConnectTargetError, ForwardTargetError,
};
use crate::context::RequestContext;
use crate::http_message::{
  Request, RequestBody, Response, build_empty_response,
  build_error_response,
};
use crate::proxy_status::{
  append_proxy_status, build_proxy_status_with_status,
};
use crate::service::Service;
use crate::stream::{self, Io};
use crate::task_tracker::TaskTracker;

// ============================================================================
// Upstream Service (unified: chain mode when upstream is Some, direct
// when None)
// ============================================================================

#[derive(Clone)]
pub(crate) struct UpstreamService {
  upstream_name: String,
  task_tracker: std::sync::Arc<TaskTracker>,
  registry: Rc<UpstreamRegistry>,
}

impl UpstreamService {
  pub(crate) fn build(
    sargs: crate::config::SerializedArgs,
    task_tracker: std::sync::Arc<TaskTracker>,
    registry: Rc<UpstreamRegistry>,
  ) -> Result<Service> {
    let args: super::config::UpstreamServiceArgs =
      serde_yaml::from_value(sargs)?;

    // Validate upstream exists in registry
    if !registry.contains_upstream(&args.upstream) {
      anyhow::bail!(
        "upstream '{}' not found in registry",
        args.upstream
      );
    }

    Ok(Service::new(Self {
      upstream_name: args.upstream,
      task_tracker,
      registry,
    }))
  }

  fn is_shutting_down(&self) -> bool {
    self.task_tracker.shutdown_handle().is_shutdown()
  }
}

impl tower::Service<Request> for UpstreamService {
  type Error = anyhow::Error;
  type Future =
    Pin<Box<dyn std::future::Future<Output = Result<Response>>>>;
  type Response = Response;

  fn poll_ready(
    &mut self,
    _cx: &mut TaskContext<'_>,
  ) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, mut req: Request) -> Self::Future {
    // Extended CONNECT changes the meaning of :authority and :path.
    // Never reinterpret an unsupported extension as a raw TCP tunnel.
    if req.extensions().get::<h3::ext::Protocol>().is_some_and(
      |protocol| *protocol != h3::ext::Protocol::CONNECT_UDP,
    ) {
      return Box::pin(async {
        Ok(build_error_response(
          http::StatusCode::NOT_IMPLEMENTED,
          "Unsupported Extended CONNECT protocol",
        ))
      });
    }
    if let Some(response) = crate::max_forwards::apply(&mut req) {
      return Box::pin(async { Ok(response) });
    }
    let upstream_name = self.upstream_name.clone();
    let st = self.task_tracker.clone();
    let registry = self.registry.clone();
    let is_shutting_down = self.is_shutting_down();

    let ctx = match req.extensions().get::<RequestContext>().cloned() {
      Some(ctx) => ctx,
      None => {
        warn!("UpstreamService: missing RequestContext");
        return Box::pin(async {
          Ok(
            UpstreamError::ProxyInternalError(
              "missing request context".into(),
            )
            .to_response(&RequestContext::new()),
          )
        });
      }
    };

    let (mut parts, body) = req.into_parts();
    match crate::connect_udp::request::recognize(&parts) {
      Ok(Some(udp)) => {
        let target = crate::connect_udp::request::target(&udp.path)
          .expect("validated UDP target");
        parts.method = http::Method::CONNECT;
        parts.uri = target.parse().expect("validated UDP authority");
        parts.extensions.insert(udp);
      }
      Ok(None) => {}
      Err(error) => {
        return Box::pin(async move {
          Ok(build_error_response(
            http::StatusCode::BAD_REQUEST,
            &error.to_string(),
          ))
        });
      }
    }
    req = Request::from_parts(parts, body);
    let upgrade = req.extensions_mut().remove::<stream::OnUpgrade>();
    let (req_headers, req_body) = req.into_parts();

    Box::pin(async move {
      if is_shutting_down {
        warn!("UpstreamService: rejecting request during shutdown");
        return Ok(
          UpstreamError::ProxyInternalError("shutting down".into())
            .to_response(&ctx),
        );
      }

      if req_headers.method == http::Method::CONNECT {
        chain_connect(
          &upstream_name,
          &registry,
          &st,
          req_headers,
          upgrade,
          &ctx,
        )
        .await
      } else {
        chain_forward(
          &upstream_name,
          &registry,
          req_headers,
          req_body,
          &ctx,
        )
        .await
      }
    })
  }
}

// ============================================================================
// Chain Mode: CONNECT
// ============================================================================

async fn chain_connect(
  upstream_name: &str,
  registry: &Rc<UpstreamRegistry>,
  st: &std::sync::Arc<TaskTracker>,
  req_headers: http::request::Parts,
  upgrade: Option<stream::OnUpgrade>,
  ctx: &RequestContext,
) -> Result<Response> {
  let target = match target_parser::parse_connect_target(&req_headers) {
    Ok(result) => result,
    Err(ConnectTargetError::NotConnectMethod) => {
      return Ok(build_error_response(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "Only CONNECT method is supported",
      ));
    }
    Err(_) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };

  let connect_start = std::time::Instant::now();
  let upstream = match registry.get_upstream(upstream_name) {
    Ok(upstream) => upstream,
    Err(e) => return Ok(e.to_response(ctx)),
  };
  let result = upstream.connect_for_tunnel(&target, &req_headers).await;
  let result = match result {
    Ok(r) => r,
    Err(e) => {
      return Ok(e.to_response(ctx));
    }
  };
  ctx.set(
    crate::context::fields::upstream::CONNECT_TIME,
    connect_start.elapsed(),
  );

  let ConnectResult {
    transport,
    upstream_addr,
    upstream_response,
    tunnel_idle_timeout,
  } = result;

  let target_io: Box<dyn Io> = transport;

  let completion = super::tunnel_log::TunnelLog::new(
    ctx,
    &target.to_string(),
    upstream_addr,
  );

  let udp = req_headers
    .extensions
    .get::<crate::connect_udp::request::Udp>()
    .cloned();
  let ingress = req_headers
    .extensions
    .get::<crate::connect_udp::h3::Ingress>()
    .cloned();
  let upgrade = upgrade.map(|upgrade| match ingress {
    Some(ingress) if udp.is_some() => {
      stream::OnUpgrade::new(UdpUpgrade {
        upgrade,
        ingress,
        tracker: registry.operation_tasks(),
      })
    }
    _ => upgrade,
  });
  let mut response = complete_tunnel(
    target_io,
    st,
    upgrade,
    ctx,
    upstream_response,
    tunnel_idle_timeout,
    completion,
  )
  .await?;
  if let Some(udp) = udp {
    response
      .headers_mut()
      .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
    if udp.http1 {
      *response.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
      response.headers_mut().insert(
        "connection",
        http::HeaderValue::from_static("Upgrade"),
      );
      response.headers_mut().insert(
        "upgrade",
        http::HeaderValue::from_static("connect-udp"),
      );
    }
  }
  Ok(response)
}

#[derive(Clone)]
struct UdpUpgrade {
  upgrade: stream::OnUpgrade,
  ingress: crate::connect_udp::h3::Ingress,
  tracker: std::sync::Arc<TaskTracker>,
}
impl std::future::Future for UdpUpgrade {
  type Output = Result<Box<dyn Io>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Self::Output> {
    let this = self.get_mut();
    Pin::new(&mut this.upgrade).poll(cx).map(|result| {
      result.map(|io| {
        this.ingress.hub.attach(
          io,
          this.ingress.id,
          this.ingress.enabled,
          &this.tracker,
        )
      })
    })
  }
}

/// Complete a CONNECT tunnel by building the 200 response and
/// registering bidirectional transfer.
///
/// Unlike ordinary response bodies, upgraded I/O leaves the listener's
/// HTTP driver. The plugin tracks this task across the upgrade handoff
/// and stops its transfer when the plugin is uninstalled.
async fn complete_tunnel(
  target: Box<dyn Io>,
  st: &std::sync::Arc<TaskTracker>,
  upgrade: Option<stream::OnUpgrade>,
  ctx: &RequestContext,
  upstream_response: Option<http::response::Parts>,
  tunnel_idle_timeout: Duration,
  completion: super::tunnel_log::TunnelLog,
) -> Result<Response> {
  let mut resp = build_tunnel_response();
  if let Some(mut upstream) = upstream_response {
    drop(crate::hop_headers::strip_connection_headers(
      &mut upstream.headers,
    ));
    crate::via::append(&mut upstream.headers, upstream.version);
    upstream.headers.remove(http::header::CONTENT_LENGTH);
    upstream.headers.remove(http::header::TRAILER);
    upstream.headers.remove(http::header::PROXY_AUTHENTICATE);
    upstream.headers.remove(http::header::PROXY_AUTHORIZATION);
    upstream.headers.remove("alt-svc");
    *resp.headers_mut() = upstream.headers;
  }
  let upstream_proxy_status =
    crate::proxy_status::take_proxy_status(resp.headers_mut());
  if let Some(ref id) =
    ctx.server_addr().map(|address| address.to_string())
  {
    let our_entry = build_proxy_status_with_status(id, 200);
    resp.headers_mut().insert(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_proxy_status.as_ref(), &our_entry),
    );
  }

  if !resp.headers().contains_key("proxy-status")
    && let Some(status) = upstream_proxy_status
  {
    resp.headers_mut().insert("proxy-status", status);
  }

  let shutdown_handle = st.shutdown_handle();

  st.register(async move {
    let client = match upgrade {
      Some(u) => match tokio::select! {
        result = u => result,
        _ = shutdown_handle.notified() => Err(anyhow::anyhow!("shutdown before tunnel upgrade")),
      } {
        Ok(c) => c,
        Err(e) => {
          completion.upgrade_failed(&e);
          return;
        }
      },
      None => {
        completion.upgrade_failed(&"no upgrade available");
        return;
      }
    };

    let end = stream::run_tunnel(
      client,
      target,
      shutdown_handle,
      tunnel_idle_timeout,
      completion.progress(),
    )
    .await;
    completion.finish(end);
  });

  Ok(resp)
}

fn build_tunnel_response() -> Response {
  build_empty_response(http::StatusCode::OK)
}

// ============================================================================
// Chain Mode: Forward
// ============================================================================

async fn chain_forward(
  upstream_name: &str,
  registry: &Rc<UpstreamRegistry>,
  req_headers: http::request::Parts,
  req_body: RequestBody,
  ctx: &RequestContext,
) -> Result<Response> {
  // Validate forward target
  let target = match target_parser::parse_forward_target(&req_headers) {
    Ok(target) => target,
    Err(ForwardTargetError::ConnectMethod) => {
      return Ok(build_error_response(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "CONNECT method not allowed for forward proxy",
      ));
    }
    Err(ForwardTargetError::UnsupportedScheme) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Only http:// and https:// schemes supported for forward proxy",
      ));
    }
    Err(_) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };

  let upstream = match registry.get_upstream(upstream_name) {
    Ok(upstream) => upstream,
    Err(e) => {
      return Ok(e.to_response(ctx));
    }
  };
  match upstream.forward(&target, req_headers, req_body, ctx).await {
    Ok(resp) => Ok(resp),
    Err(e) => Ok(e.to_response(ctx)),
  }
}
