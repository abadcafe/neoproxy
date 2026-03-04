use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::Result;
use tokio::{runtime, sync, task};
use tracing::{info, warn};

use crate::config::Config;
use crate::plugin;
use crate::plugins::PluginBuilderSet;

struct PluginSet {
  plugins: HashMap<&'static str, Box<dyn plugin::Plugin>>,
}

impl PluginSet {
  fn new() -> PluginSet {
    Self { plugins: HashMap::new() }
  }

  fn get_or_create_plugin(
    &mut self,
    name: &'static str,
  ) -> Option<&Box<dyn plugin::Plugin>> {
    let ent = self.plugins.entry(name);
    match ent {
      Entry::Vacant(ve) => {
        if let Some(builder) =
          PluginBuilderSet::global().plugin_builder(name)
        {
          Some(ve.insert(builder()))
        } else {
          None
        }
      }
      Entry::Occupied(oe) => Some(oe.into_mut()),
    }
  }
}

async fn server_thread_main(shutdown: Arc<sync::Notify>) -> Result<()> {
  let mut plugins = PluginSet::new();
  let mut services = HashMap::new();

  for sc in Config::global().services.iter() {
    let parts: Vec<&str> = sc.kind.split('.').collect();
    let plugin = plugins.get_or_create_plugin(parts[0]);
    if let None = plugin {
      // todo:
    }
    let plugin = plugin.unwrap();

    let builder = plugin.service_builder(parts[1]);
    if let None = builder {
      // todo:
    }
    let builder = builder.unwrap();

    let svc = builder(sc.args.clone())?;
    services.insert(sc.name.as_str(), svc);
  }
  info!("created services:\n{services:#?}\n");

  let mut listeners: Vec<Rc<plugin::Listener>> = Vec::new();
  let mut listener_waitings = task::JoinSet::new();
  for sc in &Config::global().servers {
    for lc in &sc.listeners {
      let parts: Vec<&str> = lc.kind.split('.').collect();
      let plugin = plugins.get_or_create_plugin(parts[0]);
      if let None = plugin {
        // todo:
      }
      let plugin = plugin.unwrap();

      let builder = plugin.listener_builder(parts[1]);
      if let None = builder {
        // todo:
      }
      let builder = builder.unwrap();

      let l: plugin::Listener = builder(
        lc.args.clone(),
        services.get(sc.service.as_str()).unwrap().clone(),
      )?;
      let l = Rc::new(l);
      listeners.push(Rc::clone(&l));
      listener_waitings.spawn_local(l.start());
    }
  }

  shutdown.notified().await;

  for l in &listeners {
    l.stop();
  }

  let res = listener_waitings.join_all().await;
  res.iter().for_each(|r| {
    let _ =
      r.as_ref().inspect_err(|&e| warn!("listener join error: {e}"));
  });

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
