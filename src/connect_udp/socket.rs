//! module: socket
//! responsibility: exchange unfragmented UDP packets with one
//! authorized peer public operations: Socket::{new,send,receive},
//! Packets::iter data entities: Socket, Packets
//! tests: socket_tests.rs, connect_udp_lifecycle_tests.rs
use std::cell::RefCell;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;

use tokio::io::Interest;

const PACKET_CAPACITY: usize = 65536;
// One spare buffer per worker, rather than one maximum GRO allocation
// per idle tunnel. Active readers hold their own buffers across writes.
thread_local! { static RECEIVE_BUFFER: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) }; }

pub(super) struct Socket {
  io: tokio::net::UdpSocket,
  state: quinn::udp::UdpSocketState,
  peer: SocketAddr,
}

pub(super) struct Packets {
  buffer: Vec<u8>,
  length: usize,
  stride: usize,
}
impl Packets {
  fn acquire(capacity: usize) -> Self {
    let buffer = RECEIVE_BUFFER
      .with(|slot| slot.borrow_mut().take())
      .filter(|buffer| buffer.len() >= capacity)
      .unwrap_or_else(|| vec![0; capacity]);
    Self { buffer, length: 0, stride: 1 }
  }

  pub(super) fn iter(&self) -> impl Iterator<Item = &[u8]> {
    (self.length == 0)
      .then_some(b"".as_slice())
      .into_iter()
      .chain(self.buffer[..self.length].chunks(self.stride))
  }
}
impl Drop for Packets {
  fn drop(&mut self) {
    // Thread teardown can already have destroyed this optional spare.
    // In that case simply release the packet allocation normally.
    let _ = RECEIVE_BUFFER.try_with(|slot| {
      let mut slot = slot.borrow_mut();
      if slot.is_none() {
        *slot = Some(std::mem::take(&mut self.buffer));
      }
    });
  }
}

impl Socket {
  pub(super) async fn new(peer: SocketAddr) -> io::Result<Self> {
    let io = tokio::net::UdpSocket::bind(if peer.is_ipv4() {
      "0.0.0.0:0"
    } else {
      "[::]:0"
    })
    .await?;
    // Quinn configures DF through its safe UDP API and treats MTU
    // send failures as packet loss. GRO requires preserving receive
    // metadata and reserving room for every coalesced datagram.
    let state = quinn::udp::UdpSocketState::new((&io).into())?;
    Ok(Self { io, state, peer })
  }

  pub(super) async fn send(&self, bytes: &[u8]) -> io::Result<()> {
    let transmit = quinn::udp::Transmit {
      destination: self.peer,
      ecn: None,
      contents: bytes,
      segment_size: None,
      src_ip: None,
    };
    loop {
      self.io.writable().await?;
      match self.io.try_io(Interest::WRITABLE, || {
        self.state.send((&self.io).into(), &transmit)
      }) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        result => return result,
      }
    }
  }

  pub(super) async fn receive(&self) -> io::Result<Packets> {
    loop {
      self.io.readable().await?;
      // Allocate only after readiness, so idle tunnels do not pin a
      // large buffer. Small buffers are unsafe semantically: some
      // backends omit MSG_TRUNC from their returned metadata.
      let capacity = PACKET_CAPACITY
        .checked_mul(self.state.gro_segments())
        .expect("UDP receive capacity fits usize");
      let mut packets = Packets::acquire(capacity);
      let mut metadata = [quinn::udp::RecvMeta::default()];
      let received = self.io.try_io(Interest::READABLE, || {
        self.state.recv(
          (&self.io).into(),
          &mut [IoSliceMut::new(&mut packets.buffer)],
          &mut metadata,
        )
      });
      let received = match received {
        Ok(received) => received,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
          continue;
        }
        Err(error) => return Err(error),
      };
      let packet = metadata[0];
      if received == 0
        || canonical(packet.addr) != canonical(self.peer)
        || packet.len > packets.buffer.len()
      {
        continue;
      }
      packets.length = packet.len;
      packets.stride = packet.stride.max(1);
      return Ok(packets);
    }
  }
}

fn canonical(address: SocketAddr) -> SocketAddr {
  match address {
    SocketAddr::V6(ipv6) if ipv6.scope_id() == 0 => ipv6
      .ip()
      .to_ipv4_mapped()
      .map_or(address, |ip| SocketAddr::new(ip.into(), ipv6.port())),
    address => address,
  }
}
