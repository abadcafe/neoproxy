#![allow(clippy::disallowed_methods, reason = "tests")]

use deno_core::unsync::spawn;

use super::tls_key::*;

fn tls_key_for_test(_sni: &str) -> TlsKey {
  let mut cert_reader = std::io::BufReader::new(&include_bytes!(
    "../../../../../conf/certs/server.crt"
  )[..]);
  let certs = crate::load_certs(&mut cert_reader).unwrap();
  let mut keys = crate::load_private_keys(include_bytes!(
    "../../../../../conf/certs/server.key"
  ))
  .unwrap();

  TlsKey(certs, keys.remove(0))
}

#[tokio::test]
async fn test_resolve_once() {
  let (resolver, lookup) = new_resolver();
  let task = spawn(async move {
    while let Some(sni) = lookup.poll().await {
      lookup.resolve(sni.clone(), Ok(tls_key_for_test(&sni)));
    }
  });

  let key = resolver.resolve("example1.com".to_owned()).await.unwrap();
  assert_eq!(tls_key_for_test("example1.com"), key);
  drop(resolver);

  task.await.unwrap();
}

#[tokio::test]
async fn test_resolve_concurrent() {
  let (resolver, lookup) = new_resolver();
  let task = spawn(async move {
    while let Some(sni) = lookup.poll().await {
      lookup.resolve(sni.clone(), Ok(tls_key_for_test(&sni)));
    }
  });

  let f1 = resolver.resolve("example1.com".to_owned());
  let f2 = resolver.resolve("example1.com".to_owned());

  let key = f1.await.unwrap();
  assert_eq!(tls_key_for_test("example1.com"), key);
  let key = f2.await.unwrap();
  assert_eq!(tls_key_for_test("example1.com"), key);
  drop(resolver);

  task.await.unwrap();
}

#[tokio::test]
async fn test_resolve_multiple_concurrent() {
  let (resolver, lookup) = new_resolver();
  let task = spawn(async move {
    while let Some(sni) = lookup.poll().await {
      lookup.resolve(sni.clone(), Ok(tls_key_for_test(&sni)));
    }
  });

  let f1 = resolver.resolve("example1.com".to_owned());
  let f2 = resolver.resolve("example2.com".to_owned());

  let key = f1.await.unwrap();
  assert_eq!(tls_key_for_test("example1.com"), key);
  let key = f2.await.unwrap();
  assert_eq!(tls_key_for_test("example2.com"), key);
  drop(resolver);

  task.await.unwrap();
}
