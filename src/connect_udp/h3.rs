//! module: h3
//! responsibility: multiplex HTTP Datagrams by request stream over QUIC
//! public operations: Hub::{new,attach}, Ingress
//! data entities: Hub, State, Ingress, Registration, Command
//! tests: CONNECT-UDP H3 process contracts
use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
#[derive(Clone)]
pub(crate) struct Hub(Arc<State>);
struct State {
  connection: quinn::Connection,
  routes: tokio::sync::mpsc::UnboundedSender<Command>,
  shutdown: crate::shutdown::ShutdownHandle,
}
enum Command {
  Register(
    u64,
    tokio::sync::mpsc::Sender<Bytes>,
    tokio::sync::oneshot::Sender<()>,
  ),
  Remove(u64),
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
    let _ = self.hub.0.routes.send(Command::Remove(self.id));
  }
}
impl Hub {
  pub(crate) fn new(
    connection: quinn::Connection,
    shutdown: crate::shutdown::ShutdownHandle,
  ) -> (Self, impl std::future::Future<Output = ()> + Send + 'static)
  {
    let (routes, mut commands) = tokio::sync::mpsc::unbounded_channel();
    let inner = Arc::new(State {
      connection: connection.clone(),
      routes,
      shutdown: shutdown.child(),
    });
    let shutdown = inner.shutdown.clone();
    let driver = async move {
      let mut routes = HashMap::new();
      loop {
        let data = tokio::select! {
          biased;
          _ = shutdown.notified() => break,
          command = commands.recv() => {
            match command {
              Some(Command::Register(id, sender, ready)) => {
                routes.insert(id, sender);
                let _ = ready.send(());
              }
              Some(Command::Remove(id)) => { routes.remove(&id); }
              None => break,
            }
            continue;
          },
          result = connection.read_datagram() => match result { Ok(data) => data, Err(_) => break },
        };
        let Some((quarter, size)) =
          super::capsule::decode_varint(&data)
        else {
          connection.close(0x33_u32.into(), b"malformed HTTP Datagram");
          break;
        };
        if quarter >= 1 << 60 {
          connection
            .close(0x33_u32.into(), b"invalid HTTP Datagram stream ID");
          break;
        }
        let id = quarter * 4;
        if let Some(sender) = routes.get(&id) {
          let _ = sender.try_send(data.slice(size..));
        }
      }
    };
    (Self(inner), driver)
  }

  pub(crate) async fn attach(
    &self,
    io: Box<dyn crate::stream::Io>,
    id: u64,
    enabled: bool,
    tracker: &crate::task_tracker::TaskTracker,
  ) -> std::io::Result<Box<dyn crate::stream::Io>> {
    let (tx, mut datagrams) = tokio::sync::mpsc::channel(64);
    let guard = Registration { hub: self.clone(), id };
    let (registered, ready) = tokio::sync::oneshot::channel();
    self.0.routes.send(Command::Register(id, tx, registered)).map_err(
      |_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted),
    )?;
    // Publish the route before a tunnel can send its first datagram.
    // The guard unregisters even if admission is cancelled while
    // queued.
    ready.await.map_err(|_| {
      std::io::Error::from(std::io::ErrorKind::ConnectionAborted)
    })?;
    let connection = self.0.connection.clone();
    Ok(super::bridge::spawn(
      tracker,
      move |bridge, shutdown| async move {
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
            Some(data)=>{
              match super::capsule::decode_varint(&data) {
                Some((0,size)) => {
                  if data.len() - size > super::capsule::MAX_UDP_PAYLOAD
                    || local_write.write_all(&super::capsule::encode(&data[size..])).await.is_err() { break; }
                },
                Some(_) => {},
                None => break,
              }
            },None=>break
           }
          }
        }
        let _ = remote_write.shutdown().await;
        let _ = local_write.shutdown().await;
      },
    ))
  }
}
