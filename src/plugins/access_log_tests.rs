use serial_test::serial;
use tower::ServiceExt;

use super::access_log::{create_plugin, plugin_name};
use crate::config::SerializedArgs;
use crate::context::RequestContext;
use crate::plugin::Plugin;

fn yaml_key(key: &str) -> serde_yaml::Value {
  serde_yaml::Value::String(key.to_string())
}

fn writer_config(path_prefix: &str) -> SerializedArgs {
  let mut writer = serde_yaml::Mapping::new();
  writer.insert(yaml_key("path_prefix"), yaml_key(path_prefix));
  writer
    .insert(yaml_key("rotate_daily"), serde_yaml::Value::Bool(false));

  let mut root = serde_yaml::Mapping::new();
  root.insert(
    yaml_key("writers"),
    serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(
      writer,
    )]),
  );
  serde_yaml::Value::Mapping(root)
}

fn empty_writer_config() -> SerializedArgs {
  let mut root = serde_yaml::Mapping::new();
  root.insert(yaml_key("writers"), serde_yaml::Value::Sequence(vec![]));
  serde_yaml::Value::Mapping(root)
}

fn layer_args(
  path_prefix: &str,
  context_fields: Vec<&str>,
) -> SerializedArgs {
  let mut root = serde_yaml::Mapping::new();
  root.insert(yaml_key("writer"), yaml_key(path_prefix));
  root.insert(
    yaml_key("context_fields"),
    serde_yaml::Value::Sequence(
      context_fields.into_iter().map(yaml_key).collect(),
    ),
  );
  serde_yaml::Value::Mapping(root)
}

fn request_with_context() -> crate::http_message::Request {
  use http_body_util::BodyExt;

  let body: crate::http_message::RequestBody =
    http_body_util::Empty::<bytes::Bytes>::new()
      .map_err(|e: std::convert::Infallible| anyhow::anyhow!("{}", e))
      .boxed_unsync();
  let mut req = http::Request::builder()
    .method(http::Method::GET)
    .uri("http://example.com/")
    .body(body)
    .unwrap();
  let ctx = RequestContext::new();
  ctx.insert("client.ip", "10.0.0.1");
  ctx.insert("client.port", "54321");
  ctx.insert("service.name", "access-log-test");
  ctx.insert("basic_auth.user", "alice");
  req.extensions_mut().insert(ctx);
  req
}

async fn call_file_layer(plugin: &dyn Plugin, path_prefix: &str) {
  let builder = plugin.layer_builder("file").unwrap();
  let layer =
    builder(layer_args(path_prefix, vec!["basic_auth.user"])).unwrap();
  let mut service = layer.layer(crate::server::placeholder_service());
  let svc = service.ready().await.unwrap();
  let response =
    tower::Service::call(svc, request_with_context()).await.unwrap();
  assert_eq!(
    response.status(),
    http::StatusCode::INTERNAL_SERVER_ERROR
  );
}

fn read_log_content(path_prefix: &str) -> String {
  let log_path = std::path::PathBuf::from(path_prefix);
  let deadline =
    std::time::Instant::now() + std::time::Duration::from_secs(3);

  loop {
    if log_path.exists()
      && let Ok(content) = std::fs::read_to_string(&log_path)
      && !content.is_empty()
    {
      return content;
    }
    if std::time::Instant::now() > deadline {
      return String::new();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
}

#[test]
fn test_access_log_plugin_name_returns_access_log() {
  assert_eq!(plugin_name(), "access_log");
}

#[tokio::test]
#[serial]
async fn test_create_plugin_has_file_layer() {
  let plugin = create_plugin(None).unwrap();
  assert!(plugin.layer_builder("file").is_some());
  plugin.uninstall().await;
}

#[tokio::test]
#[serial]
async fn test_create_plugin_no_unknown_layer() {
  let plugin = create_plugin(None).unwrap();
  assert!(plugin.layer_builder("unknown").is_none());
  plugin.uninstall().await;
}

#[tokio::test]
#[serial]
async fn test_file_layer_builds_with_writer_config() {
  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("test_layer").to_string_lossy().to_string();

  let config = writer_config(&prefix);
  let plugin = create_plugin(Some(&config)).unwrap();
  let builder = plugin.layer_builder("file").unwrap();

  let layer = builder(layer_args(&prefix, vec!["basic_auth.user"]));
  assert!(layer.is_ok());

  plugin.uninstall().await;
}

#[tokio::test]
#[serial]
async fn test_file_layer_unknown_writer_fails() {
  let config = empty_writer_config();
  let plugin = create_plugin(Some(&config)).unwrap();
  let builder = plugin.layer_builder("file").unwrap();

  let layer = builder(layer_args("logs/nonexistent", vec![]));
  assert!(layer.is_err());

  plugin.uninstall().await;
}

#[tokio::test]
#[serial]
async fn test_file_layer_builds_with_empty_context_fields() {
  let dir = tempfile::tempdir().unwrap();
  let prefix = dir.path().join("access").to_string_lossy().to_string();

  let config = writer_config(&prefix);
  let plugin = create_plugin(Some(&config)).unwrap();
  let builder = plugin.layer_builder("file").unwrap();

  let layer = builder(layer_args(&prefix, vec![]));
  assert!(layer.is_ok());

  plugin.uninstall().await;
}

#[tokio::test]
#[serial]
async fn test_uninstall_clears_file_layer_writer() {
  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("uninstall_test").to_string_lossy().to_string();

  let config = writer_config(&prefix);
  let plugin = create_plugin(Some(&config)).unwrap();
  let builder = plugin.layer_builder("file").unwrap();
  assert!(builder(layer_args(&prefix, vec![])).is_ok());

  plugin.uninstall().await;

  let builder = plugin.layer_builder("file").unwrap();
  assert!(builder(layer_args(&prefix, vec![])).is_err());
}

#[tokio::test]
#[serial]
async fn test_uninstall_flushes_file_layer_entries() {
  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("uninstall_flush").to_string_lossy().to_string();

  let config = writer_config(&prefix);
  let plugin = create_plugin(Some(&config)).unwrap();

  call_file_layer(plugin.as_ref(), &prefix).await;
  plugin.uninstall().await;

  let content = read_log_content(&prefix);
  assert!(
    content.contains("10.0.0.1"),
    "log file should contain entry data, got: {content:?}"
  );
  assert!(
    content.contains("basic_auth.user"),
    "log file should contain selected context fields, got: {content:?}"
  );
}

#[tokio::test]
#[serial]
async fn test_uninstall_returns_after_waiting_for_live_layer_sender() {
  let dir = tempfile::tempdir().unwrap();
  let prefix =
    dir.path().join("stuck_writer").to_string_lossy().to_string();

  let config = writer_config(&prefix);
  let plugin = create_plugin(Some(&config)).unwrap();
  let builder = plugin.layer_builder("file").unwrap();
  let layer = builder(layer_args(&prefix, vec![])).unwrap();
  let _service_holding_sender =
    layer.layer(crate::server::placeholder_service());

  let start = std::time::Instant::now();
  plugin.uninstall().await;
  let elapsed = start.elapsed();

  assert!(
    elapsed < std::time::Duration::from_secs(6),
    "uninstall should complete within its public shutdown budget, \
     took {:?}",
    elapsed
  );
  assert!(
    elapsed >= std::time::Duration::from_secs(4),
    "uninstall should wait for the live layer sender before \
     detaching, took {:?}",
    elapsed
  );
}

#[test]
#[serial]
fn test_create_plugin_invalid_config_returns_error() {
  let bad_config =
    serde_yaml::Value::String("not_a_valid_config".to_string());
  let result = create_plugin(Some(&bad_config));

  assert!(
    result.is_err(),
    "create_plugin should return Err on invalid config"
  );
}
