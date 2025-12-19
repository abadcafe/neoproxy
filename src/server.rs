use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::{runtime, sync, task};
use tracing::{error, info};

use crate::config::Config;
use crate::plugin;
use crate::plugins::PluginManager;

fn create_services() -> Result<HashMap<&'static str, plugin::Service>> {
  let mut services = HashMap::new();
  for sc in Config::global().services.iter() {
    let svc = PluginManager::global()
      .create_service(sc.kind.as_str(), sc.args.clone())?;
    services.insert(sc.name.as_str(), svc);
  }
  Ok(services)
}

async fn server_thread_main(
  closer: Arc<sync::Notify>,
) -> Result<()> {
  let services = create_services()?;
  info!("created services:\n{services:#?}\n");

  let mut listener_closers = vec![];
  let mut listener_waitings = task::JoinSet::new();
  for server in &Config::global().servers {
    for listener_conf in &server.listeners {
      let (mut listener, closer): (
        Box<dyn plugin::ListenerTrait>,
        Box<dyn plugin::ListenerCloserTrait>,
      ) = PluginManager::global().create_listener(
        listener_conf.kind.as_str(),
        listener_conf.args.clone(),
        services.get(server.service.as_str()).unwrap().clone(),
      )?;
      listener_closers.push(closer);
      listener_waitings.spawn_local(listener.serve());
    }
  }

  closer.notified().await;
  listener_closers.iter().for_each(|c| c.shutdown());
  listener_waitings.join_all().await;

  Ok(())
}

pub fn server_thread(
  name: &str,
  closer: Arc<sync::Notify>,
) -> Result<()> {
  let local_set = task::LocalSet::new();
  let rt = runtime::Builder::new_current_thread()
    .enable_all()
    .thread_name(name)
    .build()?;
  rt.block_on(local_set.run_until(server_thread_main(closer)))
}
