use super::message_port::{
  create_entangled_message_port, op_message_port_create_entangled,
};

#[test]
fn test_create_entangled_message_port_pairs_open_ports() {
  let (left, right) = create_entangled_message_port();

  assert!(left.tx.borrow().is_some());
  assert!(right.tx.borrow().is_some());

  left.disentangle();
  assert!(left.tx.borrow().is_none());
  assert!(right.tx.borrow().is_some());
}

#[test]
fn test_create_entangled_message_port_op_is_declared() {
  let op = op_message_port_create_entangled();

  assert_eq!(op.name, "op_message_port_create_entangled");
  assert!(!op.is_async);
}
