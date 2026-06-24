use super::url::{
  ParseStatus, op_url_parse, op_url_parse_search_params,
  op_url_stringify_search_params,
};

#[test]
fn test_parse_status_values_match_js_contract() {
  assert_eq!(ParseStatus::Ok as u32, 0);
  assert_eq!(ParseStatus::OkSerialization as u32, 1);
  assert_eq!(ParseStatus::Err as u32, 2);
}

#[test]
fn test_url_ops_are_declared() {
  assert_eq!(op_url_parse().name, "op_url_parse");
  assert_eq!(
    op_url_parse_search_params().name,
    "op_url_parse_search_params"
  );
  assert_eq!(
    op_url_stringify_search_params().name,
    "op_url_stringify_search_params"
  );
}
