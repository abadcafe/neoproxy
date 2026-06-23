#![allow(clippy::disallowed_methods, reason = "tests")]

use deno_core::unsync::spawn;

use super::tls_key::*;

fn tls_key_for_test(sni: &str) -> TlsKey {
  let manifest_dir =
    std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
  let sni = sni.replace(".com", "");
  let cert_file = manifest_dir.join(format!("testdata/{}_cert.der", sni));
  let prikey_file = manifest_dir.join(format!("testdata/{}_prikey.der", sni));
  let cert = std::fs::read(cert_file).unwrap();
  let prikey = std::fs::read(prikey_file).unwrap();
  let cert = CertificateDer::from(cert);
  let prikey = PrivateKeyDer::try_from(prikey).unwrap();
  TlsKey(vec![cert], prikey)
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
