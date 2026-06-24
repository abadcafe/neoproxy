use super::inject_ops::{
  op_sandbox_read_request, op_sandbox_write_response,
};

#[test]
fn test_op_sandbox_read_request_declares_sync_state_arg_op() {
  let op = op_sandbox_read_request();

  assert_eq!(op.name, "op_sandbox_read_request");
  assert!(!op.is_async);
  assert_eq!(op.arg_count, 1);
}

#[test]
fn test_op_sandbox_write_response_declares_sync_state_and_payload_op() {
  let op = op_sandbox_write_response();

  assert_eq!(op.name, "op_sandbox_write_response");
  assert!(!op.is_async);
  assert_eq!(op.arg_count, 4);
}
