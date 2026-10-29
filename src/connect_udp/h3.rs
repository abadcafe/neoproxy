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
  task: Mutex<Option<tokio::task::AbortHandle>>,
}
impl Drop for State {
  fn drop(&mut self) {
    if let Some(task) =
      self.task.get_mut().expect("datagram task lock").take()
    {
      task.abort();
    }
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
  pub(crate) fn new(connection: quinn::Connection) -> Self {
    let inner = Arc::new(State {
      connection: connection.clone(),
      routes: Mutex::new(HashMap::new()),
      task: Mutex::new(None),
    });
    let weak = Arc::downgrade(&inner);
    let task = tokio::spawn(async move {
      while let Ok(data) = connection.read_datagram().await {
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
    *inner.task.lock().expect("datagram task lock") =
      Some(task.abort_handle());
    Self(inner)
  }

  pub(crate) fn attach(
    &self,
    io: Box<dyn crate::stream::Io>,
    id: u64,
    enabled: bool,
  ) -> Box<dyn crate::stream::Io> {
    let (tx, mut datagrams) = tokio::sync::mpsc::channel(64);
    self.0.routes.lock().expect("datagram routes lock").insert(id, tx);
    let guard = Registration { hub: self.clone(), id };
    let connection = self.0.connection.clone();
    let (client, bridge) = tokio::io::duplex(131072);
    tokio::spawn(async move {
      let _guard = guard;
      let (local_read, mut local_write) = tokio::io::split(bridge);
      let (remote_read, mut remote_write) = tokio::io::split(io);
      let mut outgoing = super::capsule::Reader::new(local_read);
      let mut incoming = super::capsule::Reader::new(remote_read);
      loop {
        tokio::select! {
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
    });
    Box::new(client)
  }
}
