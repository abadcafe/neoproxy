#![forbid(unsafe_code)]

//! module: main
//! responsibility: coordinate process configuration and worker
//! ownership
//! public operations: CLI process entry
//! data entities: none
//! tests: tests/integration process contracts

use std::thread;

use anyhow::Result;
use tokio::runtime;
use tracing::info;

use crate::cli::CmdOpt;
use crate::config::{Config, ConfigErrorCollector};
use crate::shutdown::ShutdownHandle;

mod auth;
mod certificate;
#[cfg(test)]
mod certificate_tests;
mod cli;
mod config;
mod connect_udp;
#[cfg(test)]
mod connect_udp_lifecycle_tests;
#[cfg(test)]
mod connect_udp_tests;
mod context;
mod h3_response;
#[cfg(test)]
mod h3_response_tests;
mod h3_stream;
mod hop_headers;
#[cfg(test)]
mod hop_headers_tests;
mod hostname;
#[cfg(test)]
mod hostname_tests;
mod http_authority;
#[cfg(test)]
mod http_authority_tests;
mod http_message;
mod io_stream;
mod listener;
mod listeners;
mod logging;
mod max_forwards;
#[cfg(test)]
mod max_forwards_tests;
mod plugin;
#[cfg(test)]
mod plugin_tests;
mod plugins;
#[cfg(test)]
mod plugins_tests;
mod process;
mod proxy_status;
#[cfg(test)]
mod proxy_status_tests;
mod quic_datagram;
#[cfg(test)]
mod quic_datagram_tests;
mod redaction;
#[cfg(test)]
mod redaction_tests;
mod request_id;
#[cfg(test)]
mod request_id_tests;
mod retained_cache;
#[cfg(test)]
mod retained_cache_tests;
mod server;
#[cfg(test)]
mod server_fixtures;
mod server_thread;
mod service;
mod shutdown;
mod startup;
#[cfg(test)]
mod startup_tests;
mod stream;
#[cfg(test)]
mod stream_transfer_tests;
mod task_tracker;
#[cfg(test)]
mod task_tracker_background_tests;
mod tls;
mod via;
#[cfg(test)]
mod via_tests;
mod worker_runtime;
#[cfg(test)]
mod worker_runtime_tests;
mod worker_shutdown;
#[cfg(test)]
mod worker_shutdown_tests;

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod listeners_tests;

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod h3_stream_read_tests;
#[cfg(test)]
mod h3_stream_tests;
#[cfg(test)]
mod h3_stream_write_tests;
#[cfg(test)]
mod http_message_tests;
#[cfg(test)]
mod process_tests;
#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod server_thread_tests;
#[cfg(test)]
mod service_tests;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod stream_tunnel_tests;
#[cfg(test)]
mod task_tracker_tests;
#[cfg(test)]
mod tls_selection_tests;
#[cfg(test)]
mod tls_tests;

fn main() -> Result<std::process::ExitCode> {
  // Load config
  let config = Config::load(CmdOpt::global().config_file())?;

  // Install rustls crypto provider based on config
  tls::install_provider(config.tls_provider().unwrap_or("ring"))?;

  // Validate config
  let mut collector = ConfigErrorCollector::new();
  let listener_manager = listeners::ListenerManager::new();
  config.validate(&mut collector, &listener_manager);
  if collector.has_errors() {
    collector.report_and_exit();
  }
  config.compile_tls()?;

  // Initialize logging after config is loaded
  let _guard = logging::init("logs/")?;

  info!(
    "server starting with {} workers; config: {:#?}",
    config.server_threads(),
    config
  );

  // Create the process-owned access log registry.
  let log_registry = if config.plugins().contains_key("access_log") {
    Some(plugins::access_log::build_registry(
      config.plugins().get("access_log"),
    )?)
  } else {
    None
  };
  let connection_pools = config
    .plugins()
    .get("upstream")
    .map(|args| {
      plugins::upstream::build_connection_pools(Some(args)).inspect_err(
        |error| {
          tracing::error!(
            "connection pool initialization failed: {error:#}"
          )
        },
      )
    })
    .transpose()?;
  let policies = config
    .plugins()
    .get("e2b")
    .map(plugins::e2b::SharedPolicies::new)
    .transpose()?;
  // Create shutdown signal
  let shutdown = ShutdownHandle::new();

  // Spawn server threads (each builds its own PluginManager and
  // listeners)
  let rt =
    runtime::Builder::new_current_thread().enable_all().build()?;
  let signal = process::shutdown_signal(rt.handle())?;
  // Workers borrow the same configuration. The scope guarantees all
  // workers have exited before that configuration can be dropped.
  let exit_code = thread::scope(|scope| -> Result<i32> {
    let config = &config;
    let mut supervisor = process::Workers::new(shutdown.clone());
    let startup = startup::participants(
      config.server_threads(),
      std::env::var_os("NOTIFY_SOCKET"),
      shutdown.clone(),
    )?;
    let mut workers = worker_shutdown::participants(
      config.server_threads(),
      shutdown.clone(),
    )
    .into_iter()
    .zip(startup)
    .enumerate();
    while let Some((i, (worker, readiness))) = workers.next() {
      let log_registry = log_registry.clone();
      let connection_pools = connection_pools.clone();
      let policies = policies.clone();
      if let Err(error) = supervisor.spawn(
        scope,
        &format!("neoproxy-server-{i}"),
        move || {
          server_thread::run_server_thread(
            config,
            log_registry,
            connection_pools,
            policies,
            worker,
            readiness,
            i,
          )
        },
      ) {
        shutdown.shutdown();
        // Unstarted participants must leave before joining workers
        // which can already be waiting at transport release.
        drop(workers);
        return Err(error.into());
      }
    }

    // Supervise and explicitly join workers within their borrow scope.
    Ok(rt.block_on(async {
      let running = supervisor.run(signal);
      if let Some(pools) = &connection_pools {
        tokio::select! {
          exit = running => exit,
          () = pools.monitor() => unreachable!("pool monitoring never completes"),
        }
      } else {
        running.await
      }
    }))
  })?;

  if let Some(shared) = &connection_pools {
    shared.shutdown();
  }

  // Drop the process-owned writers before the diagnostic log guard.
  drop(log_registry);

  Ok(std::process::ExitCode::from(exit_code as u8))
}

mod tcp_options;
#[cfg(test)]
mod tcp_options_tests;

mod header_limits;
#[cfg(test)]
mod header_limits_tests;

mod h3_io_deadline;
#[cfg(test)]
mod h3_io_deadline_tests;

mod io_progress;
#[cfg(test)]
mod io_progress_tests;
