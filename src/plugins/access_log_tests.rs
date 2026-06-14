use serial_test::serial;

use super::access_log::test_utils::TracingCapture;
use super::access_log::{
  AccessLogPlugin, LogEntry, WRITER_JOIN_TIMEOUT, config, context,
  create_plugin, get_writer, layer, reset_writer_registry,
};
use crate::plugin::Plugin;

#[test]
#[serial]
fn test_access_log_plugin_has_file_layer() {
  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  assert!(plugin.layer_builder("file").is_some());
}

#[test]
#[serial]
fn test_access_log_plugin_no_unknown_layer() {
  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  assert!(plugin.layer_builder("unknown").is_none());
}

#[test]
#[serial]
fn test_access_log_file_layer_builds_with_writer_config() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("test_layer").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  let builder = plugin.layer_builder("file").unwrap();
  let args = serde_yaml::from_str(&format!(
    r#"
writer: "{}"
context_fields:
  - basic_auth.user
"#,
    prefix
  ))
  .unwrap();
  let layer = builder(args);
  assert!(layer.is_ok());
}

#[test]
#[serial]
fn test_access_log_file_layer_unknown_writer_fails() {
  reset_writer_registry();

  let plugin_config = config::AccessLogPluginConfig { writers: vec![] };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  let builder = plugin.layer_builder("file").unwrap();
  let args = serde_yaml::from_str(
    r#"
writer: "logs/nonexistent"
"#,
  )
  .unwrap();
  let layer = builder(args);
  assert!(layer.is_err());
}

#[test]
#[serial]
fn test_access_log_file_layer_builds_with_empty_config() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix = dir.path().join("access").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  let builder = plugin.layer_builder("file").unwrap();
  let args = serde_yaml::from_str(&format!(
    r#"
writer: "{}"
"#,
    prefix
  ))
  .unwrap();
  let layer = builder(args);
  assert!(layer.is_ok());
}

#[test]
#[serial]
fn test_access_log_file_layer_builds_with_context_fields() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix = dir.path().join("access").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let _plugin = create_plugin(Some(&config_value)).unwrap();

  let plugin = AccessLogPlugin::new(std::sync::Arc::new(
    std::sync::atomic::AtomicBool::new(false),
  ));
  let builder = plugin.layer_builder("file").unwrap();
  let args = serde_yaml::from_str(&format!(
    r#"
writer: "{}"
context_fields:
  - basic_auth.user
"#,
    prefix
  ))
  .unwrap();
  let layer = builder(args);
  assert!(layer.is_ok());
}

#[tokio::test]
#[serial]
async fn test_access_log_plugin_uninstall_joins_writer_threads() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("uninstall_join").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let plugin = create_plugin(Some(&config_value)).unwrap();

  let writer = get_writer(&prefix);
  assert!(
    writer.is_ok(),
    "Writer should be accessible before uninstall"
  );
  drop(writer);

  let uninstall_result = tokio::time::timeout(
    std::time::Duration::from_secs(5),
    plugin.uninstall(),
  )
  .await;
  assert!(
    uninstall_result.is_ok(),
    "uninstall should complete within timeout"
  );

  let writer_after = get_writer(&prefix);
  assert!(
    writer_after.is_err(),
    "Writer should not be accessible after uninstall"
  );

  let log_path = std::path::PathBuf::from(&prefix);
  let _ = log_path;
}

#[tokio::test]
#[serial]
async fn test_access_log_plugin_uninstall_clears_registry() {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("uninstall_test").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let plugin = create_plugin(Some(&config_value)).unwrap();

  let writer = get_writer(&prefix);
  assert!(
    writer.is_ok(),
    "Writer should be accessible before uninstall"
  );
  drop(writer);

  plugin.uninstall().await;

  let writer_after = get_writer(&prefix);
  assert!(
    writer_after.is_err(),
    "Writer should not be accessible after uninstall"
  );
}

#[tokio::test]
#[serial]
async fn test_access_log_plugin_uninstall_returns_quickly_with_stuck_writer()
 {
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("stuck_writer").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let plugin = create_plugin(Some(&config_value)).unwrap();

  let _sender = get_writer(&prefix).unwrap();

  let start = std::time::Instant::now();
  plugin.uninstall().await;
  let elapsed = start.elapsed();

  assert!(
    elapsed
      < WRITER_JOIN_TIMEOUT + std::time::Duration::from_millis(500),
    "uninstall should complete within timeout margin, took {:?}",
    elapsed
  );
  assert!(
    elapsed >= WRITER_JOIN_TIMEOUT,
    "uninstall should have waited for timeout, took {:?}",
    elapsed
  );

  let writer_after = get_writer(&prefix);
  assert!(
    writer_after.is_err(),
    "Writer should not be accessible after uninstall"
  );

  drop(_sender);
}

#[tokio::test]
#[serial]
async fn test_uninstall_joins_writer_threads_and_flushes_data() {
  // uninstall() now joins writer threads directly (no separate
  // flush_writer_threads step). When all sender clones are dropped
  // before uninstall, the writer thread should exit and flush its
  // data within WRITER_JOIN_TIMEOUT.
  reset_writer_registry();

  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("uninstall_flush").to_string_lossy().to_string();

  let plugin_config = config::AccessLogPluginConfig {
    writers: vec![config::AccessLogWriterConfig {
      path_prefix: prefix.clone(),
      buffer_capacity: byte_unit::Byte::from_u64(1024 * 1024),
      flush_interval: std::time::Duration::from_secs(3600),
      rotate_daily: false,
      ..Default::default()
    }],
  };
  let config_value = serde_yaml::to_value(&plugin_config).unwrap();
  let plugin = create_plugin(Some(&config_value)).unwrap();

  // Send a log entry and drop our sender so writer thread can exit
  let sender = get_writer(&prefix).unwrap();
  let entry = LogEntry {
    entry: context::AccessLogEntry {
      time: time::OffsetDateTime::now_utc(),
      client_ip: "10.0.0.1".to_string(),
      client_port: 54321,
      server_ip: "0.0.0.0".to_string(),
      server_port: 8080,
      method: "GET".to_string(),
      target: "http://uninstall.test/".to_string(),
      status: 200,
      duration_ms: 7,
      service: "test".to_string(),
      err: None,
      extensions: std::collections::HashMap::new(),
    },
  };
  sender.try_send(entry).unwrap();
  std::thread::sleep(std::time::Duration::from_millis(100));
  drop(sender);

  // uninstall should join the writer thread (no sender clones held)
  let start = std::time::Instant::now();
  plugin.uninstall().await;
  let elapsed = start.elapsed();
  assert!(
    elapsed < std::time::Duration::from_secs(3),
    "uninstall should join quickly when no sender clones held, took \
     {:?}",
    elapsed
  );

  // Verify the log file contains the entry
  let log_path = std::path::PathBuf::from(&prefix);
  let deadline =
    std::time::Instant::now() + std::time::Duration::from_secs(3);
  let mut content = String::new();
  loop {
    if log_path.exists() {
      if let Ok(c) = std::fs::read_to_string(&log_path) {
        if !c.is_empty() {
          content = c;
          break;
        }
      }
    }
    if std::time::Instant::now() > deadline {
      break;
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
  assert!(
    !content.is_empty(),
    "Log file should contain the written entry"
  );
  assert!(
    content.contains("10.0.0.1"),
    "Log file should contain entry data"
  );
}

#[test]
#[serial]
fn test_create_plugin_invalid_config_returns_error() {
  reset_writer_registry();

  let bad_config =
    serde_yaml::Value::String("not_a_valid_config".to_string());
  let result = create_plugin(Some(&bad_config));

  assert!(
    result.is_err(),
    "create_plugin should return Err on invalid config"
  );
}

#[tokio::test]
#[serial]
async fn test_try_send_on_full_channel_logs_warning() {
  use http_body_util::BodyExt;
  use tower::{Layer, ServiceExt};

  // --- Test Full case ---
  {
    let (capture, _guard) = TracingCapture::new();

    let (tx, _rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
    let dummy_entry = LogEntry {
      entry: context::AccessLogEntry {
        time: time::OffsetDateTime::now_utc(),
        client_ip: String::new(),
        client_port: 0,
        server_ip: String::new(),
        server_port: 0,
        method: String::new(),
        target: String::new(),
        status: 0,
        duration_ms: 0,
        service: String::new(),
        err: None,
        extensions: std::collections::HashMap::new(),
      },
    };
    tx.try_send(dummy_entry).unwrap();

    let access_log_layer =
      layer::AccessLogLayer { tx, context_fields: vec![] };
    let inner = crate::server::placeholder_service();
    let mut service = Layer::layer(&access_log_layer, inner);

    let body: crate::http_utils::RequestBody =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com/")
      .body(body)
      .unwrap();
    let svc = service.ready().await.unwrap();
    let _ = tower::Service::call(svc, req).await;

    let output = capture.output();
    assert!(
      output.contains("channel full"),
      "tracing should capture 'channel full' warning from middleware, \
       got: {:?}",
      &output[..output.len().min(500)]
    );
  }

  // --- Test Closed case ---
  {
    let (capture, _guard) = TracingCapture::new();

    let (tx, rx) = std::sync::mpsc::sync_channel::<LogEntry>(1);
    drop(rx);

    let access_log_layer =
      layer::AccessLogLayer { tx, context_fields: vec![] };
    let inner = crate::server::placeholder_service();
    let mut service = Layer::layer(&access_log_layer, inner);

    let body: crate::http_utils::RequestBody =
      http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
        .boxed_unsync();
    let req = http::Request::builder()
      .method("GET")
      .uri("http://example.com/")
      .body(body)
      .unwrap();
    let svc = service.ready().await.unwrap();
    let _ = tower::Service::call(svc, req).await;

    let output = capture.output();
    assert!(
      output.contains("channel closed"),
      "tracing should capture 'channel closed' warning from \
       middleware, got: {:?}",
      &output[..output.len().min(500)]
    );
  }
}
