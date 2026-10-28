//! module: nodes
//! responsibility: schedule resolved peers with passive failure
//! accounting public operations:
//! Nodes::{update,select,failed,succeeded}, NodeKey, NodePolicy
//! data entities: Nodes, NodeKey, NodePolicy, Node
//! tests: nodes_tests.rs
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(super) struct NodeKey {
  pub(super) owner: usize,
  pub(super) address: SocketAddr,
}
#[derive(Clone)]
pub(super) struct NodePolicy {
  pub(super) key: NodeKey,
  pub(super) weight: usize,
  pub(super) max_fails: usize,
  pub(super) fail_timeout: Duration,
}
struct Node {
  policy: NodePolicy,
  current: i128,
  effective: i128,
  fails: usize,
  accessed: Instant,
  checked: Instant,
}
#[derive(Default)]
pub(super) struct Nodes {
  peers: HashMap<NodeKey, Node>,
  order: Vec<NodeKey>,
}
impl Nodes {
  pub(super) fn update(&mut self, policies: Vec<NodePolicy>) {
    self.order = policies.iter().map(|p| p.key.clone()).collect();
    self.peers.retain(|key, _| self.order.contains(key));
    for policy in policies {
      self
        .peers
        .entry(policy.key.clone())
        .and_modify(|node| node.policy = policy.clone())
        .or_insert_with(|| Node {
          current: 0,
          effective: policy.weight as i128,
          policy,
          fails: 0,
          accessed: Instant::now(),
          checked: Instant::now(),
        });
    }
  }

  pub(super) fn select(
    &mut self,
    tried: &[NodeKey],
  ) -> Option<NodeKey> {
    let single = self.peers.len() == 1;
    let now = Instant::now();
    let mut best: Option<(NodeKey, i128)> = None;
    let mut total = 0;
    for key in &self.order {
      let peer =
        self.peers.get_mut(key).expect("node order is synchronized");
      if tried.contains(key)
        || (!single
          && peer.policy.max_fails != 0
          && peer.fails >= peer.policy.max_fails
          && now.duration_since(peer.checked)
            <= peer.policy.fail_timeout)
      {
        continue;
      }
      peer.current += peer.effective;
      total += peer.effective;
      if peer.effective < peer.policy.weight as i128 {
        peer.effective += 1;
      }
      if best.as_ref().is_none_or(|(_, weight)| peer.current > *weight)
      {
        best = Some((key.clone(), peer.current));
      }
    }
    let (key, _) = best?;
    let peer = self.peers.get_mut(&key).expect("selected node exists");
    peer.current -= total;
    if now.duration_since(peer.checked) > peer.policy.fail_timeout {
      peer.checked = now;
    }
    Some(key)
  }

  pub(super) fn failed(&mut self, key: &NodeKey) {
    if self.peers.len() == 1 {
      if let Some(peer) = self.peers.get_mut(key) {
        peer.fails = 0;
      }
      return;
    }
    if let Some(peer) = self.peers.get_mut(key) {
      peer.fails = peer.fails.saturating_add(1);
      peer.accessed = Instant::now();
      peer.checked = peer.accessed;
      if let Some(penalty) =
        peer.policy.weight.checked_div(peer.policy.max_fails)
      {
        peer.effective = (peer.effective - penalty as i128).max(0);
      }
    }
  }

  pub(super) fn succeeded(&mut self, key: &NodeKey) {
    let single = self.peers.len() == 1;
    if let Some(peer) = self.peers.get_mut(key)
      && (single || peer.accessed < peer.checked)
    {
      peer.fails = 0;
    }
  }
}

/// Cross-worker scheduling preserves weights and health within one
/// upstream.
#[derive(Default)]
pub(super) struct SharedNodes(std::sync::Mutex<Nodes>);
impl SharedNodes {
  pub(super) fn update(&self, policies: Vec<NodePolicy>) {
    self.0.lock().expect("nodes poisoned").update(policies);
  }

  pub(super) fn select(
    &self,
    tried: &[NodeKey],
    excluded_owners: &[usize],
  ) -> Option<NodeKey> {
    let mut nodes = self.0.lock().expect("nodes poisoned");
    let mut excluded = tried.to_vec();
    excluded.extend(
      nodes
        .order
        .iter()
        .filter(|key| excluded_owners.contains(&key.owner))
        .cloned(),
    );
    nodes.select(&excluded)
  }

  pub(super) fn failed(&self, key: &NodeKey) {
    self.0.lock().expect("nodes poisoned").failed(key);
  }

  pub(super) fn succeeded(&self, key: &NodeKey) {
    self.0.lock().expect("nodes poisoned").succeeded(key);
  }
}
