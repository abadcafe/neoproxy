use std::sync::Arc;

use super::keylog::get_ssl_key_log;

#[test]
fn test_get_ssl_key_log_returns_singleton_logger() {
  let first = get_ssl_key_log();
  let second = get_ssl_key_log();

  assert!(Arc::ptr_eq(&first, &second));
}
