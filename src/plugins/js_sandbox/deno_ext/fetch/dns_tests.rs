use std::str::FromStr;

use super::dns::*;

// A resolver that resolves any name into the same address.
#[derive(Debug)]
struct DebugResolver(SocketAddr);

impl Resolve for DebugResolver {
  fn resolve(&self, _name: Name) -> Resolving {
    let addr = self.0;
    Box::pin(async move { Ok(vec![addr].into_iter()) })
  }
}

#[tokio::test]
async fn custom_dns_resolver() {
  let mut resolver = Resolver::Custom(Arc::new(DebugResolver(
    "127.0.0.1:8080".parse().unwrap(),
  )));
  let mut addr = resolver
    .call(Name::from_str("foo.com").unwrap())
    .await
    .unwrap();

  let addr = addr.next().unwrap();
  assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());
}
