//! module: runtime
//! responsibility: dispatch upstream exchanges through resolved healthy
//! peer pools public operations:
//! Upstream::{new,forward,connect_for_tunnel,close} data entities:
//! Upstream, Group tests: client_tests.rs, test_upstream_nodes.py
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use super::nodes::{NodeKey, NodePolicy, SharedNodes};
use super::protocol::ConnectResult;
use super::retry_request::{Progress, RetryRequest};
use super::transport_factory::{self, ClientEntry};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::upstream::config;
use crate::plugins::upstream::error::UpstreamError;
use crate::plugins::upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

#[derive(Default)]
struct Group {
  nodes: Arc<SharedNodes>,
  clients: HashMap<NodeKey, Rc<ClientEntry>>,
  addresses: Vec<config::Address>,
}
impl Group {
  fn failed(&mut self, key: &NodeKey, selected: &Rc<ClientEntry>) {
    if self
      .clients
      .get(key)
      .is_some_and(|current| Rc::ptr_eq(current, selected))
    {
      self.nodes.failed(key);
    }
  }

  fn succeeded(&mut self, key: &NodeKey, selected: &Rc<ClientEntry>) {
    if self
      .clients
      .get(key)
      .is_some_and(|current| Rc::ptr_eq(current, selected))
    {
      self.nodes.succeeded(key);
    }
  }
}
pub(crate) struct Upstream {
  connection_pools: Arc<super::ConnectionPools>,
  name: String,
  config: config::Upstream,
  tracker: Rc<StreamTracker>,
  groups: RefCell<HashMap<String, Rc<RefCell<Group>>>>,
}
impl Upstream {
  pub(super) fn new(
    config: config::Upstream,
    tracker: Rc<StreamTracker>,
    connection_pools: Arc<super::ConnectionPools>,
    name: String,
  ) -> Self {
    Self {
      connection_pools,
      name,
      config,
      tracker,
      groups: RefCell::new(HashMap::new()),
    }
  }

  fn addresses(&self, uri: &http::Uri) -> Vec<config::Address> {
    if !self.config.addresses.is_empty() {
      return self.config.addresses.clone();
    }
    let authority =
      uri.authority().expect("validated request authority");
    let https = uri.scheme_str() == Some("https");
    let port =
      authority.port_u16().unwrap_or(if https { 443 } else { 80 });
    let address = format!("{}:{port}", authority.host());
    vec![config::Address {
      use_connection_pool: self.config.use_connection_pool.clone(),
      address,
      hostname: None,
      weight: 1,
      address_protocol: if https {
        config::Protocol::Https {
          connect_timeout: self.config.connect_timeout,
          tls_handshake_timeout: self.config.tls_handshake_timeout,
        }
      } else {
        config::Protocol::Http {
          connect_timeout: self.config.connect_timeout,
        }
      },
      address_max_fails: self.config.address_max_fails,
      address_fail_timeout: self.config.address_fail_timeout,
      tcp_keep_alive_time: self.config.tcp_keep_alive_time,
      tcp_keep_alive_interval: self.config.tcp_keep_alive_interval,
      tcp_keep_alive_retries: self.config.tcp_keep_alive_retries,
      upstream_read_timeout: self.config.upstream_read_timeout,
      upstream_send_timeout: self.config.upstream_send_timeout,
      tunnel_idle_timeout: self.config.tunnel_idle_timeout,
      user: None,
    }]
  }

  async fn group(
    &self,
    uri: &http::Uri,
    ctx: Option<&RequestContext>,
  ) -> Result<Rc<RefCell<Group>>, UpstreamError> {
    let addresses = self.addresses(uri);
    let key = if self.config.addresses.is_empty() {
      format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("connect"),
        addresses[0].address
      )
    } else {
      String::new()
    };
    let results = futures_util::future::join_all(addresses.iter().map(
      |address| async move {
        self
          .connection_pools
          .get(&address.use_connection_pool)
          .dns
          .resolve(&address.address, ctx)
          .await
      },
    ))
    .await;
    let mut policies = Vec::new();
    let mut error = None;
    for (owner, result) in results.into_iter().enumerate() {
      match result {
        Ok(ips) => {
          let address = &addresses[owner];
          let mut unique = std::collections::HashSet::new();
          for ip in ips {
            if unique.insert(ip) {
              policies.push(NodePolicy {
                key: NodeKey { owner, address: ip },
                weight: address.weight,
                max_fails: address.address_max_fails,
                fail_timeout: address.address_fail_timeout,
              });
            }
          }
        }
        Err(failure) => error = Some(failure),
      }
    }
    if policies.is_empty() {
      return Err(error.unwrap_or_else(|| {
        UpstreamError::DnsError("no upstream addresses".into())
      }));
    }
    let group = self
      .groups
      .borrow_mut()
      .entry(key.clone())
      .or_insert_with(|| {
        Rc::new(RefCell::new(Group {
          nodes: self
            .connection_pools
            .nodes((self.name.clone(), key.clone())),
          clients: HashMap::new(),
          addresses: addresses.clone(),
        }))
      })
      .clone();
    {
      let mut group = group.borrow_mut();
      group.clients.retain(|key, _| {
        policies.iter().any(|policy| &policy.key == key)
      });
      for policy in &policies {
        if !group.clients.contains_key(&policy.key) {
          let client = transport_factory::build(
            &self.config,
            &addresses[policy.key.owner],
            policy.key.address,
            &self.tracker,
            &self.connection_pools,
          )?;
          group.clients.insert(policy.key.clone(), Rc::new(client));
        }
      }
      group.nodes.update(policies);
    }
    Ok(group)
  }

  pub(crate) async fn forward(
    &self,
    target: &ForwardTarget,
    req_headers: http::request::Parts,
    req_body: RequestBody,
    ctx: &RequestContext,
  ) -> Result<Response, UpstreamError> {
    if !self.config.addresses.is_empty()
      && self.config.addresses.iter().all(|address| {
        matches!(
          address.address_protocol,
          config::Protocol::Socks5 { .. }
        )
      })
    {
      return Err(UpstreamError::DestinationUnavailable(
        "no available upstream peers".into(),
      ));
    }
    if self.config.addresses.is_empty() {
      let protocol = match target.absolute_uri().scheme_str() {
        Some("http") => config::protocol::ProtocolKind::Http,
        Some("https") => config::protocol::ProtocolKind::Https,
        _ => unreachable!("forward target has a validated HTTP scheme"),
      };
      ctx.set(
        crate::context::fields::upstream::PROTOCOL,
        Arc::from(protocol.as_str()),
      );
    }
    let group = self.group(target.absolute_uri(), Some(ctx)).await?;
    let request = RetryRequest::new(req_body);
    // Incompatible peers are excluded without changing health or
    // weights.
    let excluded: Vec<usize> = self
      .config
      .addresses
      .iter()
      .enumerate()
      .filter_map(|(owner, address)| {
        matches!(
          address.address_protocol,
          config::Protocol::Socks5 { .. }
        )
        .then_some(owner)
      })
      .collect();
    self
      .dispatch(
        group,
        excluded,
        Some(ctx),
        |progress| {
          request.can_retry(
            progress,
            &req_headers.method,
            self.config.upstream_non_idempotent_retry,
          )
        },
        async |selected, progress| {
          let mut parts = req_headers.clone();
          parts.extensions.insert(progress);
          parts.extensions.insert(selected.timeouts);
          selected
            .client
            .forward(
              &Some(selected.tls.clone()),
              &self.tracker,
              target,
              parts,
              request.body(),
              ctx,
            )
            .await
        },
      )
      .await
  }

  pub(crate) async fn connect_for_tunnel(
    &self,
    target: &ConnectTarget,
    request: &http::request::Parts,
  ) -> Result<ConnectResult, UpstreamError> {
    let ctx = request.extensions.get::<RequestContext>();
    let group = self.group(&target.uri(), ctx).await?;
    self
      .dispatch(
        group,
        Vec::new(),
        ctx,
        |_| true,
        async |selected, progress| {
          let mut request = request.clone();
          request.extensions.insert(progress);
          request.extensions.insert(selected.timeouts);
          selected
            .client
            .connect_for_tunnel(
              target,
              &request,
              &Some(selected.tls.clone()),
              &self.tracker,
            )
            .await
        },
      )
      .await
  }

  async fn dispatch<T, F, R>(
    &self,
    group: Rc<RefCell<Group>>,
    excluded: Vec<usize>,
    ctx: Option<&RequestContext>,
    replayable: R,
    mut execute: F,
  ) -> Result<T, UpstreamError>
  where
    F:
      AsyncFnMut(Rc<ClientEntry>, Progress) -> Result<T, UpstreamError>,
    R: Fn(&Progress) -> bool,
  {
    let mut tried = Vec::new();
    let mut last_error = None;
    loop {
      let key = group.borrow().nodes.select(&tried, &excluded);
      let Some(key) = key else {
        return Err(last_error.unwrap_or_else(|| {
          UpstreamError::DestinationUnavailable(
            "no available upstream peers".into(),
          )
        }));
      };
      tried.push(key.clone());
      // Another worker may have refreshed DNS after this worker's
      // group snapshot. Instantiate the selected connection_pools peer
      // locally instead of indexing a potentially older client map.
      let selected = {
        let mut group = group.borrow_mut();
        if !group.clients.contains_key(&key) {
          let client = transport_factory::build(
            &self.config,
            &group.addresses[key.owner],
            key.address,
            &self.tracker,
            &self.connection_pools,
          )?;
          group.clients.insert(key.clone(), Rc::new(client));
        }
        group.clients[&key].clone()
      };
      if let Some(ctx) = ctx
        && (!self.config.addresses.is_empty()
          || !matches!(
            selected.protocol,
            config::protocol::ProtocolKind::Http
          ))
      {
        ctx.set(
          crate::context::fields::upstream::PROTOCOL,
          Arc::from(selected.protocol.as_str()),
        );
      }
      let progress = Progress::default();
      let result = execute(selected.clone(), progress.clone()).await;
      match result {
        Ok(value) => {
          group.borrow_mut().succeeded(&key, &selected);
          return Ok(value);
        }
        Err(error) => {
          // Local capacity and downstream cancellation never penalize a
          // peer.
          if !counts_failure(&error) {
            if matches!(
              error,
              UpstreamError::UpstreamConnectError { .. }
                | UpstreamError::InvalidResponse(_)
            ) {
              group.borrow_mut().succeeded(&key, &selected);
            }
            return Err(error);
          }
          group.borrow_mut().failed(&key, &selected);
          if !replayable(&progress) {
            return Err(error);
          }
          last_error = Some(error);
        }
      }
    }
  }

  pub(super) fn close(&self) {
    for group in self.groups.borrow().values() {
      for client in group.borrow().clients.values() {
        client.client.close();
      }
    }
  }
}
fn counts_failure(error: &UpstreamError) -> bool {
  matches!(
    error,
    UpstreamError::ConnectionRefused(_)
      | UpstreamError::ConnectionTimeout(_)
      | UpstreamError::ConnectionTerminated(_)
      | UpstreamError::TlsCertificateError(_)
      | UpstreamError::TlsProtocolError(_)
      | UpstreamError::DestinationUnavailable(_)
  )
}
