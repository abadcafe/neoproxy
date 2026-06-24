use super::{forgiving_base64_encode, op_base64_encode};

#[test]
fn test_forgiving_base64_encode_encodes_binary_input() {
  assert_eq!(forgiving_base64_encode(b"hello"), "aGVsbG8=");
}

#[test]
fn test_base64_encode_op_is_declared() {
  let op = op_base64_encode();

  assert_eq!(op.name, "op_base64_encode");
  assert!(!op.is_async);
}
