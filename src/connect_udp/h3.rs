//! module: h3
//! responsibility: multiplex HTTP Datagrams by request stream over QUIC
//! public operations: Hub::{new,attach}, Ingress
//! data entities: Hub, State, Ingress, Registration
//! tests: CONNECT-UDP H3 process contracts
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
#[derive(Clone)]
pub(crate) struct Hub(Arc<State>);
struct State {
  connection: quinn::Connection,
  routes: Mutex<HashMap<u64, tokio::sync::mpsc::Sender<Bytes>>>,
  shutdown: crate::shutdown::ShutdownHandle,
}
impl Drop for State {
  fn drop(&mut self) {
    self.shutdown.shutdown();
  }
}
#[derive(Clone)]
pub(crate) struct Ingress {
  pub(crate) hub: Hub,
  pub(crate) id: u64,
  pub(crate) enabled: bool,
}
struct Registration {
  hub: Hub,
  id: u64,
}
impl Drop for Registration {
  fn drop(&mut self) {
    self
      .hub
      .0
      .routes
      .lock()
      .expect("datagram routes lock")
      .remove(&self.id);
  }
}
impl Hub {
  pub(crate) fn new(
    connection: quinn::Connection,
    tasks: &crate::task_tracker::TaskTracker,
  ) -> Self {
    let inner = Arc::new(State {
      connection: connection.clone(),
      routes: Mutex::new(HashMap::new()),
      shutdown: tasks.shutdown_handle().child(),
    });
    let weak = Arc::downgrade(&inner);
    let shutdown = inner.shutdown.clone();
    tasks.register_on(&tokio::runtime::Handle::current(), async move {
      loop {
        let data = tokio::select! {
          biased;
          _ = shutdown.notified() => break,
          result = connection.read_datagram() => match result { Ok(data) => data, Err(_) => break },
        };
        let Some((quarter, size)) =
          super::capsule::decode_varint(&data)
        else {
          connection.close(0x33_u32.into(), b"malformed HTTP Datagram");
          break;
        };
        let Some(id) = quarter.checked_mul(4) else {
          connection
            .close(0x33_u32.into(), b"invalid HTTP Datagram stream ID");
          break;
        };
        let Some(state) = weak.upgrade() else {
          break;
        };
        if let Some(sender) =
          state.routes.lock().expect("datagram routes lock").get(&id)
        {
          let _ = sender.try_send(data.slice(size..));
        }
      }
    });
    Self(inner)
  }

  pub(crate) fn attach(
    &self,
    io: Box<dyn crate::stream::Io>,
    id: u64,
    enabled: bool,
    tracker: &crate::task_tracker::TaskTracker,
  ) -> Box<dyn crate::stream::Io> {
    let (tx, mut datagrams) = tokio::sync::mpsc::channel(64);
    self.0.routes.lock().expect("datagram routes lock").insert(id, tx);
    let guard = Registration { hub: self.clone(), id };
    let connection = self.0.connection.clone();
    super::bridge::spawn(tracker, move |bridge, shutdown| async move {
      let _guard = guard;
      let (local_read, mut local_write) = tokio::io::split(bridge);
      let (remote_read, mut remote_write) = tokio::io::split(io);
      let mut outgoing = super::capsule::Reader::new(local_read);
      let mut incoming = super::capsule::Reader::new(remote_read);
      loop {
        tokio::select! {
         biased;
         _ = shutdown.notified() => break,
         packet=outgoing.receive()=>match packet {
          Ok(Some(data))=>{
           let mut wire=Vec::new();super::capsule::varint(id/4,&mut wire);wire.push(0);wire.extend_from_slice(&data);
           if enabled && connection.max_datagram_size().is_some_and(|max|wire.len()<=max) {
            if connection.send_datagram(wire.into()).is_err(){break;}
           } else {
            // H3 AsyncWrite accepts into a bounded buffer. Flush each
            // capsule so an isolated UDP packet never waits for another.
            if remote_write.write_all(&super::capsule::encode(&data)).await.is_err() || remote_write.flush().await.is_err(){break;}
           }
          },_=>break
         },
         packet=incoming.receive()=>match packet {Ok(Some(data))=>{if local_write.write_all(&super::capsule::encode(&data)).await.is_err(){break;}},_=>break},
         packet=datagrams.recv()=>match packet {
          Some(data)=>{if let Some((0,size))=super::capsule::decode_varint(&data) && local_write.write_all(&super::capsule::encode(&data[size..])).await.is_err(){break;}},None=>break
         }
        }
      }
      let _ = remote_write.shutdown().await;
      let _ = local_write.shutdown().await;
    })
  }
}
