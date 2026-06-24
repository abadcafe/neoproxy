use super::console::op_preview_entries;

#[test]
fn test_preview_entries_op_is_declared() {
  let op = op_preview_entries();

  assert_eq!(op.name, "op_preview_entries");
  assert!(!op.is_async);
}
