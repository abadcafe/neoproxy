#[cfg(test)]
mod tests {
  use tokio::task;

  #[test]
  fn test_server_thread_runtime_creation() {
    let rt = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .thread_name("test_thread")
      .build();
    assert!(rt.is_ok());
  }

  #[test]
  fn test_server_thread_local_set_creation() {
    let local_set = task::LocalSet::new();
    drop(local_set);
  }
}
