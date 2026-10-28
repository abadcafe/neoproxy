//! Black-box contracts for DNS refresh coalescing and zero-TTL expiry.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::future::join_all;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use super::dns_cache::DnsCache;

async fn resolve_batches(
  batch_sizes: &[usize],
) -> Vec<Vec<RecordType>> {
  let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let cache = DnsCache::new(
    Some(&[socket.local_addr().unwrap()]),
    Duration::from_secs(5),
    Duration::from_secs(30),
  )
  .unwrap();
  let queries = RefCell::new(Vec::new());
  let (finished, mut stop) = oneshot::channel();
  let clients = async {
    let mut snapshots = Vec::new();
    for &size in batch_sizes {
      let mut pending = (0..size)
        .map(|_| Box::pin(cache.resolve("origin.test:443", None)))
        .collect::<Vec<_>>();
      // Explicitly poll every public resolve future before allowing the
      // DNS server to run. All calls are pending before any reply is
      // possible. No sleep, subprocess startup, or cache-internal
      // inspection is used.
      for request in &mut pending {
        assert!(futures::poll!(request.as_mut()).is_pending());
      }
      for result in join_all(pending).await {
        assert_eq!(
          result.unwrap(),
          vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 443))]
        );
      }
      snapshots.push(queries.borrow().clone());
    }
    finished.send(()).unwrap();
    snapshots
  };
  let server = async {
    let mut buffer = [0; 4096];
    loop {
      let (length, peer) = tokio::select! {
        _ = &mut stop => break,
        packet = socket.recv_from(&mut buffer) => packet.unwrap(),
      };
      let request = Message::from_vec(&buffer[..length]).unwrap();
      assert_eq!(request.queries.len(), 1);
      let query = &request.queries[0];
      assert_eq!(query.name().to_ascii(), "origin.test.");
      queries.borrow_mut().push(query.query_type());
      let mut reply = Message::response(
        request.metadata.id,
        request.metadata.op_code,
      );
      reply.metadata.recursion_desired =
        request.metadata.recursion_desired;
      reply.metadata.recursion_available = true;
      reply.edns = request.edns.clone();
      reply.add_query(query.clone());
      match query.query_type() {
        RecordType::A => {
          reply.add_answer(Record::from_rdata(
            query.name().clone(),
            0,
            RData::A(A(Ipv4Addr::LOCALHOST)),
          ));
        }
        RecordType::AAAA => {}
        other => panic!("unexpected DNS query: {other}"),
      }
      socket.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
    }
  };
  // Watchdog only: correctness is controlled by polling and reply
  // ordering.
  tokio::time::timeout(Duration::from_secs(10), async {
    let (snapshots, ()) = tokio::join!(clients, server);
    snapshots
  })
  .await
  .unwrap()
}

#[tokio::test]
async fn test_resolve_concurrent_zero_ttl_calls_share_one_refresh() {
  let snapshots = resolve_batches(&[6]).await;
  assert_eq!(snapshots.len(), 1);
  assert_eq!(snapshots[0].len(), 2);
  assert!(snapshots[0].contains(&RecordType::A));
  assert!(snapshots[0].contains(&RecordType::AAAA));
}

#[tokio::test]
async fn test_resolve_later_zero_ttl_call_starts_new_refresh() {
  let snapshots = resolve_batches(&[1, 1]).await;
  assert_eq!(snapshots[0].len(), 2);
  assert_eq!(snapshots[1].len(), 4);
  for kind in [RecordType::A, RecordType::AAAA] {
    assert_eq!(
      snapshots[1].iter().filter(|&&seen| seen == kind).count(),
      2
    );
  }
}
