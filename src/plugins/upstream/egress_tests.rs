use std::net::IpAddr;
use std::sync::Arc;

use super::egress::{DestinationPolicy, Proxy, Route};
struct AllowLoopback;
impl DestinationPolicy for AllowLoopback {
  fn allows(&self, _: &str, ip: IpAddr) -> bool {
    ip.is_loopback()
  }
}
#[test]
fn test_new_proxy_validates_authority() {
  for address in ["proxy.test:1080", "[::1]:1080"] {
    assert!(Proxy::new(address.into(), None, None).is_ok());
  }
  for address in
    ["proxy.test", "proxy.test:0", "user:pass@proxy.test:1080"]
  {
    assert!(Proxy::new(address.into(), None, None).is_err());
  }
}
#[test]
fn test_new_route_preserves_authorization_and_remote_dns() {
  let route = Route::new(Arc::new(AllowLoopback), None, false);
  assert!(route.allows("host", "127.0.0.1".parse().unwrap()));
  assert!(!route.allows("host", "1.1.1.1".parse().unwrap()));
  assert!(!route.remote_dns());
  assert!(route.proxy().is_none());
}
