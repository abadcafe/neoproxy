//! Packet boundary and peer filtering contracts over real UDP sockets.
use quinn::Runtime;

use super::socket::Socket;

#[tokio::test]
async fn test_receive_preserves_boundaries_of_segmented_udp_transmission()
 {
  let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
  peer
    .set_read_timeout(Some(std::time::Duration::from_secs(1)))
    .unwrap();
  let socket = Socket::new(peer.local_addr().unwrap()).await.unwrap();
  socket.send(b"hello").await.unwrap();
  let mut buffer = [0; 65536];
  let (_, local) = peer.recv_from(&mut buffer).unwrap();
  peer.set_nonblocking(true).unwrap();
  let peer = quinn::TokioRuntime.wrap_udp_socket(peer).unwrap();
  let mut poller = peer.clone().create_io_poller();
  let content =
    [b"a".repeat(32), b"b".repeat(32), b"c".repeat(7)].concat();
  // Respect the sender's batching capability. Linux can use GSO;
  // macOS without fast-apple-datapath accepts one datagram per send.
  // Both paths must deliver the same three original packet boundaries.
  for contents in content.chunks(32 * peer.max_transmit_segments()) {
    let transmit = quinn::udp::Transmit {
      destination: local,
      contents,
      segment_size: Some(32),
      ecn: None,
      src_ip: None,
    };
    loop {
      match peer.try_send(&transmit) {
        Ok(()) => break,
        Err(error)
          if error.kind() == std::io::ErrorKind::WouldBlock =>
        {
          std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap()
        }
        Err(error) => panic!("UDP transmission failed: {error}"),
      }
    }
  }
  let mut received = Vec::new();
  while received.len() < 3 {
    let packets = tokio::time::timeout(
      std::time::Duration::from_secs(1),
      socket.receive(),
    )
    .await
    .unwrap()
    .unwrap();
    received.extend(packets.iter().map(<[u8]>::to_vec));
  }
  assert_eq!(
    received,
    vec![b"a".repeat(32), b"b".repeat(32), b"c".repeat(7)]
  );
}

#[tokio::test]
async fn test_receive_filters_other_sources_and_preserves_empty_datagrams()
 {
  let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let rogue = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let socket = Socket::new(peer.local_addr().unwrap()).await.unwrap();
  socket.send(b"hello").await.unwrap();
  let mut buffer = [0; 65536];
  let (length, local) = peer.recv_from(&mut buffer).await.unwrap();
  assert_eq!(&buffer[..length], b"hello");
  rogue.send_to(b"wrong-peer", local).await.unwrap();
  peer.send_to(b"", local).await.unwrap();
  let packets = tokio::time::timeout(
    std::time::Duration::from_secs(1),
    socket.receive(),
  )
  .await
  .unwrap()
  .unwrap();
  assert_eq!(packets.iter().collect::<Vec<_>>(), vec![b"".as_slice()]);
}

#[tokio::test]
async fn test_receive_accepts_ipv6_and_ipv4_mapped_peer_addresses() {
  for bind in ["127.0.0.1:0", "[::1]:0"] {
    let peer = tokio::net::UdpSocket::bind(bind).await.unwrap();
    let address = peer.local_addr().unwrap();
    let destination = match address {
      std::net::SocketAddr::V4(ipv4) => std::net::SocketAddr::new(
        ipv4.ip().to_ipv6_mapped().into(),
        ipv4.port(),
      ),
      address => address,
    };
    let socket = Socket::new(destination).await.unwrap();
    socket.send(b"out").await.unwrap();
    let mut bytes = [0; 32];
    let (_, source) = tokio::time::timeout(
      std::time::Duration::from_secs(1),
      peer.recv_from(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    peer.send_to(b"reply", source).await.unwrap();
    let received = tokio::time::timeout(
      std::time::Duration::from_secs(1),
      socket.receive(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
      received.iter().collect::<Vec<_>>(),
      vec![b"reply".as_slice()]
    );
  }
}
