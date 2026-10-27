//! module: runtime
//! responsibility: dispatch upstream exchanges through resolved healthy
//! peer pools public operations:
//! Upstream::{new,forward,connect_for_tunnel,close} data entities:
//! Upstream, Group tests: upstream_tests.rs, test_upstream_nodes.py
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use super::dns_cache::DnsCache;
use super::nodes::{NodeKey, NodePolicy, Nodes};
use super::protocol::ConnectResult;
use super::retry_request::{Progress, RetryRequest};
use super::transport_factory::{self, ClientEntry};
use crate::context::RequestContext;
use crate::http_message::{RequestBody, Response};
use crate::plugins::http_upstream::config;
use crate::plugins::http_upstream::error::UpstreamError;
use crate::plugins::http_upstream::target_parser::{
  ConnectTarget, ForwardTarget,
};
use crate::tracker::StreamTracker;

#[derive(Default)]
struct Group {
  nodes: Nodes,
  clients: HashMap<NodeKey, Rc<ClientEntry>>,
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
  config: config::Upstream,
  dns: Rc<DnsCache>,
  tls: Option<Arc<rustls::ClientConfig>>,
  tracker: Rc<StreamTracker>,
  groups: RefCell<HashMap<String, Rc<RefCell<Group>>>>,
}
impl Upstream {
  pub(super) fn new(
    config: config::Upstream,
    dns: Rc<DnsCache>,
    tls: Option<Arc<rustls::ClientConfig>>,
    tracker: Rc<StreamTracker>,
  ) -> Self {
    Self {
      config,
      dns,
      tls,
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
      upstream_request_timeout: self.config.upstream_request_timeout,
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
    let results = futures_util::future::join_all(
      addresses
        .iter()
        .map(|address| self.dns.resolve(&address.address, ctx)),
    )
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
    let group =
      self.groups.borrow_mut().entry(key).or_default().clone();
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
            &self.tls,
            &self.tracker,
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
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
    target: &ForwardTarget,
    req_headers: http::request::Parts,
    req_body: RequestBody,
    ctx: &RequestContext,
  ) -> Result<Response, UpstreamError> {
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
    let mut tried = Vec::new();
    let mut last_error = None;
    loop {
      let Some(key) = group.borrow_mut().nodes.select(&tried) else {
        return Err(last_error.unwrap_or_else(|| {
          UpstreamError::DestinationUnavailable(
            "no available upstream peers".into(),
          )
        }));
      };
      tried.push(key.clone());
      let selected = group.borrow().clients[&key].clone();
      ctx.set(
        crate::context::fields::upstream::PROTOCOL,
        Arc::from(selected.protocol.as_str()),
      );
      let mut parts = req_headers.clone();
      let progress = Progress::default();
      parts.extensions.insert(progress.clone());
      let result = tokio::time::timeout(
        selected.request_timeout,
        selected.client.forward(
          tls_config,
          tracker,
          target,
          parts,
          request.body(),
          ctx,
        ),
      )
      .await;
      let timed_out = result.is_err();
      let result = match result {
        Ok(result) => result,
        Err(_) => Err(UpstreamError::ConnectionTimeout(
          "upstream response header deadline exceeded".into(),
        )),
      };
      match result {
        Ok(response) => {
          group.borrow_mut().succeeded(&key, &selected);
          return Ok(response);
        }
        Err(error) => {
          if counts_failure(&error) {
            group.borrow_mut().failed(&key, &selected);
          } else {
            if matches!(
              error,
              UpstreamError::UpstreamConnectError { .. }
                | UpstreamError::InvalidResponse(_)
            ) {
              group.borrow_mut().succeeded(&key, &selected);
            }
            return Err(error);
          }
          if !request.can_retry(&progress) {
            if timed_out {
              ctx.set(
                crate::context::fields::upstream::ERROR_PHASE,
                Arc::from("response_headers"),
              );
            }
            return Err(error);
          }
          last_error = Some(error);
        }
      }
    }
  }

  pub(crate) async fn connect_for_tunnel(
    &self,
    target: &ConnectTarget,
    request: &http::request::Parts,
    tls_config: &Option<Arc<rustls::ClientConfig>>,
    tracker: &Rc<StreamTracker>,
  ) -> Result<ConnectResult, UpstreamError> {
    let ctx = request.extensions.get::<RequestContext>();
    let group = self.group(&target.uri(), ctx).await?;
    let mut tried = Vec::new();
    let mut last_error = None;
    loop {
      let Some(key) = group.borrow_mut().nodes.select(&tried) else {
        return Err(last_error.unwrap_or_else(|| {
          UpstreamError::DestinationUnavailable(
            "no available upstream peers".into(),
          )
        }));
      };
      tried.push(key.clone());
      let selected = group.borrow().clients[&key].clone();
      if !self.config.addresses.is_empty()
        && let Some(ctx) = ctx
      {
        ctx.set(
          crate::context::fields::upstream::PROTOCOL,
          Arc::from(selected.protocol.as_str()),
        );
      }
      let result = tokio::time::timeout(
        selected.request_timeout,
        selected
          .client
          .connect_for_tunnel(target, request, tls_config, tracker),
      )
      .await
      .unwrap_or_else(|_| {
        Err(UpstreamError::ConnectionTimeout(
          "upstream tunnel establishment deadline exceeded".into(),
        ))
      });
      match result {
        Ok(result) => {
          group.borrow_mut().succeeded(&key, &selected);
          return Ok(result);
        }
        Err(error) => {
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
