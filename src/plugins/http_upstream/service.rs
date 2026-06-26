use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::Result;
use tracing::warn;

use super::error::UpstreamError;
use super::target_parser::{
  self, ConnectTargetError, ForwardTargetError,
};
use super::upstream::{ConnectResult, UpstreamRegistry};
use crate::context::{RequestContext, get_server_id};
use crate::http_message::{
  Request, RequestBody, Response, append_proxy_status,
  build_empty_response, build_error_response,
  build_proxy_status_with_status,
};
use crate::service::Service;
use crate::stream::{self, Io};
use crate::tracker::StreamTracker;

// ============================================================================
// Upstream Service (unified: chain mode when upstream is Some, direct
// when None)
// ============================================================================

#[derive(Clone)]
pub(crate) struct UpstreamService {
  upstream_name: String,
  stream_tracker: Rc<StreamTracker>,
  registry: Rc<RefCell<UpstreamRegistry>>,
}

impl UpstreamService {
  #[allow(clippy::new_ret_no_self)]
  pub(crate) fn new(
    sargs: crate::config::SerializedArgs,
    stream_tracker: Rc<StreamTracker>,
    registry: Rc<RefCell<UpstreamRegistry>>,
  ) -> Result<Service> {
    let args: super::config::UpstreamServiceArgs =
      serde_yaml::from_value(sargs)?;

    // Validate upstream exists in registry
    if !registry.borrow().contains_upstream(&args.upstream) {
      anyhow::bail!(
        "upstream '{}' not found in registry",
        args.upstream
      );
    }

    Ok(Service::new(Self {
      upstream_name: args.upstream,
      stream_tracker,
      registry,
    }))
  }

  fn is_shutting_down(&self) -> bool {
    self.stream_tracker.shutdown_handle().is_shutdown()
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
    let upstream_name = self.upstream_name.clone();
    let st = self.stream_tracker.clone();
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

    let upgrade = stream::extract_upgrade(&mut req);
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
  registry: &Rc<RefCell<UpstreamRegistry>>,
  st: &Rc<StreamTracker>,
  req_headers: http::request::Parts,
  upgrade: Option<stream::UpgradeFuture>,
  ctx: &RequestContext,
) -> Result<Response> {
  let (host, port) =
    match target_parser::parse_connect_target(&req_headers) {
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
  let target = format!("{host}:{port}");

  let (tls_config, tracker) = {
    let reg = registry.borrow();
    (reg.tls_config(), reg.tracker())
  };

  let connect_start = std::time::Instant::now();
  let upstream = match registry.borrow().get_upstream(upstream_name) {
    Ok(upstream) => upstream,
    Err(e) => return Ok(e.to_response(ctx)),
  };
  let result =
    upstream.connect_for_tunnel(&target, &tls_config, &tracker).await;
  let result = match result {
    Ok(r) => r,
    Err(e) => {
      warn!("UpstreamService: CONNECT to upstream failed: {e}");
      return Ok(e.to_response(ctx));
    }
  };
  let connect_ms = connect_start.elapsed().as_millis() as u64;
  ctx.insert("upstream.connect_ms", connect_ms.to_string());

  let ConnectResult {
    transport,
    upstream_addr,
    upstream_proxy_status,
    tunnel_idle_timeout,
  } = result;

  let target_io: Box<dyn Io> = transport;

  let client_addr = format!(
    "{}:{}",
    ctx.get("client.ip").unwrap_or_default(),
    ctx.get("client.port").unwrap_or_default(),
  );
  let upstream_ip =
    upstream_addr.map(|a| format!(" ({a})")).unwrap_or_default();
  let tunnel_desc = format!("{client_addr} -> {target}{upstream_ip}");

  complete_tunnel(
    target_io,
    st,
    upgrade,
    ctx,
    upstream_proxy_status,
    tunnel_idle_timeout,
    &tunnel_desc,
  )
  .await
}

/// Complete a CONNECT tunnel by building the 200 response and
/// registering bidirectional transfer.
async fn complete_tunnel(
  target: Box<dyn Io>,
  st: &Rc<StreamTracker>,
  upgrade: Option<stream::UpgradeFuture>,
  ctx: &RequestContext,
  upstream_proxy_status: Option<http::HeaderValue>,
  tunnel_idle_timeout: Duration,
  tunnel_desc: &str,
) -> Result<Response> {
  let mut resp = build_tunnel_response();
  if let Some(ref id) = get_server_id(ctx) {
    let our_entry = build_proxy_status_with_status(id, 200);
    resp.headers_mut().insert(
      http::header::HeaderName::from_static("proxy-status"),
      append_proxy_status(upstream_proxy_status.as_ref(), &our_entry),
    );
  }

  let shutdown_handle = st.shutdown_handle();
  let tunnel_desc = tunnel_desc.to_string();

  st.register(async move {
    let client = match upgrade {
      Some(u) => match u.await {
        Ok(c) => c,
        Err(e) => {
          warn!("tunnel {tunnel_desc} upgrade failed: {e}");
          return;
        }
      },
      None => {
        warn!("tunnel {tunnel_desc}: no upgrade available");
        return;
      }
    };

    stream::run_tunnel(
      client,
      target,
      shutdown_handle,
      tunnel_idle_timeout,
      &tunnel_desc,
    )
    .await;
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
  registry: &Rc<RefCell<UpstreamRegistry>>,
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
        "Only http:// scheme supported for forward proxy",
      ));
    }
    Err(_) => {
      return Ok(build_error_response(
        http::StatusCode::BAD_REQUEST,
        "Invalid target address",
      ));
    }
  };

  let (tls_config, tracker) = {
    let reg = registry.borrow();
    (reg.tls_config(), reg.tracker())
  };

  let upstream = match registry.borrow().get_upstream(upstream_name) {
    Ok(upstream) => upstream,
    Err(e) => {
      warn!("UpstreamService: failed to get upstream for forward: {e}");
      return Ok(e.to_response(ctx));
    }
  };
  match upstream
    .forward(&tls_config, &tracker, &target, req_headers, req_body, ctx)
    .await
  {
    Ok(resp) => Ok(resp),
    Err(e) => {
      warn!("UpstreamService: forward failed: {e}");
      Ok(e.to_response(ctx))
    }
  }
}
