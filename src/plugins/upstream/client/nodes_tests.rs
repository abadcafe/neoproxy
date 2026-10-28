use std::time::Duration;

use super::nodes::{NodeKey, NodePolicy, Nodes};

fn policy(index: usize, weight: usize) -> NodePolicy {
  NodePolicy {
    key: NodeKey {
      owner: index,
      address: format!("127.0.0.1:{}", 8000 + index).parse().unwrap(),
    },
    weight,
    max_fails: 1,
    fail_timeout: Duration::from_secs(10),
  }
}

#[tokio::test(start_paused = true)]
async fn test_nodes_weight_failure_and_recovery() {
  let mut nodes = Nodes::default();
  let policies = vec![policy(0, 2), policy(1, 1)];
  nodes.update(policies.clone());
  let mut counts = [0; 2];
  for _ in 0..30 {
    counts[nodes.select(&[]).unwrap().owner] += 1;
  }
  assert_eq!(counts, [20, 10]);
  nodes.failed(&policies[0].key);
  for _ in 0..5 {
    assert_eq!(nodes.select(&[]).unwrap().owner, 1);
  }
  nodes.update(policies.clone());
  assert_eq!(nodes.select(&[]).unwrap().owner, 1);
  tokio::time::advance(Duration::from_secs(11)).await;
  let recovered = nodes.select(&[policies[1].key.clone()]).unwrap();
  assert_eq!(recovered.owner, 0);
  nodes.succeeded(&recovered);
  nodes.update(vec![policies[1].clone()]);
  assert_eq!(nodes.select(&[]).unwrap().owner, 1);
}

#[test]
fn test_nodes_single_peer_and_disabled_failures_remain_selectable() {
  let mut nodes = Nodes::default();
  let one = policy(0, 1);
  nodes.update(vec![one.clone()]);
  nodes.failed(&one.key);
  assert_eq!(nodes.select(&[]), Some(one.key.clone()));
  let mut other = policy(1, 1);
  other.max_fails = 0;
  nodes.update(vec![one.clone(), other.clone()]);
  nodes.failed(&other.key);
  assert_eq!(nodes.select(&[one.key]), Some(other.key));
}

#[tokio::test(start_paused = true)]
async fn test_nodes_failure_threshold_and_successful_probe_reset() {
  let mut nodes = Nodes::default();
  let mut a = policy(0, 1);
  a.max_fails = 2;
  let b = policy(1, 1);
  nodes.update(vec![a.clone(), b.clone()]);
  nodes.failed(&a.key);
  assert_eq!(
    nodes.select(std::slice::from_ref(&b.key)),
    Some(a.key.clone())
  );
  nodes.failed(&a.key);
  assert_eq!(nodes.select(std::slice::from_ref(&b.key)), None);
  tokio::time::advance(Duration::from_secs(11)).await;
  assert_eq!(
    nodes.select(std::slice::from_ref(&b.key)),
    Some(a.key.clone())
  );
  nodes.succeeded(&a.key);
  nodes.failed(&a.key);
  assert_eq!(nodes.select(std::slice::from_ref(&b.key)), Some(a.key));
}

#[test]
fn test_shared_nodes_preserve_weights_and_health_across_threads() {
  let nodes = std::sync::Arc::new(super::nodes::SharedNodes::default());
  let first = policy(0, 2);
  nodes.update(vec![first.clone(), policy(1, 1)]);
  let counts = std::thread::scope(|scope| {
    let handles: Vec<_> = (0..4)
      .map(|_| {
        let nodes = nodes.clone();
        scope.spawn(move || {
          let mut counts = [0; 2];
          for _ in 0..75 {
            counts[nodes.select(&[], &[]).unwrap().owner] += 1;
          }
          counts
        })
      })
      .collect();
    handles.into_iter().fold([0; 2], |mut total, handle| {
      let counts = handle.join().unwrap();
      total[0] += counts[0];
      total[1] += counts[1];
      total
    })
  });
  assert_eq!(counts, [200, 100]);
  let reporting = nodes.clone();
  std::thread::spawn(move || reporting.failed(&first.key))
    .join()
    .unwrap();
  assert_eq!(nodes.select(&[], &[]).unwrap().owner, 1);
}

#[test]
fn test_shared_nodes_exclude_protocol_owner_after_dns_refresh() {
  let nodes = super::nodes::SharedNodes::default();
  nodes.update(vec![policy(0, 1), policy(1, 10)]);
  let mut refreshed = policy(1, 10);
  refreshed.key.address = "127.0.0.2:8001".parse().unwrap();
  nodes.update(vec![policy(0, 1), refreshed]);
  for _ in 0..10 {
    assert_eq!(nodes.select(&[], &[1]).unwrap().owner, 0);
  }
}
