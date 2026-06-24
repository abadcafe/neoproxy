use std::sync::Arc;

use deno_core::url::Url;

use super::blob::{Blob, BlobStore, InMemoryBlobPart};

#[tokio::test]
async fn test_blob_read_all_concatenates_parts() {
  let blob = Blob {
    media_type: "text/plain".to_string(),
    parts: vec![
      Arc::new(InMemoryBlobPart::from(b"hello ".to_vec())),
      Arc::new(InMemoryBlobPart::from(b"world".to_vec())),
    ],
  };

  assert_eq!(blob.read_all().await, b"hello world");
}

#[test]
fn test_blob_store_object_url_lookup_ignores_fragment() {
  let store = BlobStore::default();
  let blob = Blob {
    media_type: "text/plain".to_string(),
    parts: vec![Arc::new(InMemoryBlobPart::from(b"body".to_vec()))],
  };
  let url = store.insert_object_url(blob, None);
  let with_fragment = Url::parse(&format!("{url}#section")).unwrap();

  assert!(store.get_object_url(with_fragment).is_some());

  store.remove_object_url(&url);
  assert!(store.get_object_url(url).is_none());
}
