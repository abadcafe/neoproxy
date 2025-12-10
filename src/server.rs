use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use tokio::{runtime, sync, task};

use crate::config::Config;
use crate::plugin;
use crate::plugins::PluginManager;

async fn server_thread_main(
  services: HashMap<&str, plugin::Service>,
  closer: Arc<sync::Notify>,
) -> Result<()> {
  let mut listener_closers = vec![];
  let mut listener_waitings = task::JoinSet::new();
  for server in &Config::global().servers {
    for listener_conf in &server.listeners {
      let (listener, closer): (
        Box<dyn plugin::ListenerTrait>,
        Box<dyn plugin::ListenerCloserTrait>,
      ) = PluginManager::global().create_listener(
        listener_conf.kind.as_str(),
        listener_conf.args.clone(),
        services.get(server.service.as_str()).unwrap().clone(),
      )?;
      let listener: Rc<dyn plugin::ListenerTrait> = listener.into();
      listener_waitings.spawn_local(listener.serve());
      listener_closers.push(closer);
    }
  }

  closer.notified().await;
  listener_closers.iter().for_each(|c| c.shutdown());
  listener_waitings.join_all().await;

  Ok(())
}

pub fn server_thread(
  services: HashMap<&str, plugin::Service>,
  closer: Arc<sync::Notify>,
) -> Result<()> {
  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name("neoproxy server thread")
    .build()?;
  rt.block_on(local_set.run_until(server_thread_main(services, closer)))
}
