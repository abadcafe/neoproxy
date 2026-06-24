use deno_core::url::Url;

use super::{FetchOptions, extract_authority, init_fetch};

#[test]
fn test_fetch_options_default_has_no_root_cert_store() {
  let options = FetchOptions::default();

  assert!(options.root_cert_store().unwrap().is_none());
}

#[test]
fn test_init_fetch_builds_extension_from_options() {
  let _extension = init_fetch(FetchOptions::default());
}

#[test]
fn test_extract_authority_decodes_and_removes_userinfo() {
  let mut url =
    Url::parse("https://us%2Fer:p%2Fass@example.com/path").unwrap();

  let authority = extract_authority(&mut url);

  assert_eq!(authority, Some(("us/er".to_string(), Some("p/ass".to_string()))));
  assert_eq!(url.as_str(), "https://example.com/path");
}

#[test]
fn test_extract_authority_ignores_urls_without_userinfo() {
  let mut url = Url::parse("https://example.com/path").unwrap();

  assert!(extract_authority(&mut url).is_none());
  assert_eq!(url.as_str(), "https://example.com/path");
}
