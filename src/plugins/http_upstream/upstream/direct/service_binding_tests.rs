//! Black-box contracts for advertised DNS protocols and connection
//! routes.

use hickory_resolver::proto::rr::Name;
use hickory_resolver::proto::rr::rdata::svcb::{
  Alpn, SVCB, SvcParamKey, SvcParamValue,
};

use super::origin::{Origin, Route, WireProtocol};
use super::service_binding::ServiceBinding;

#[test]
fn test_alternative_requires_advertised_protocol_intersection() {
  let origin =
    Origin::from_uri(&"https://origin.test/".parse().unwrap()).unwrap();
  for no_default in [false, true] {
    let mut params = vec![(
      SvcParamKey::Alpn,
      SvcParamValue::Alpn(Alpn(vec!["h3".into()])),
    )];
    if no_default {
      params.push((
        SvcParamKey::NoDefaultAlpn,
        SvcParamValue::NoDefaultAlpn,
      ));
    }
    let record =
      SVCB::new(1, Name::from_ascii("bound.test.").unwrap(), params);
    let binding =
      ServiceBinding::from_record(&record, &origin, "origin.test")
        .unwrap();
    for (protocol, allowed) in [
      (WireProtocol::Http3, true),
      (WireProtocol::Http2, false),
      (WireProtocol::Http1, !no_default),
    ] {
      let alternative =
        Route { host: "advertised.test".into(), port: 8443, protocol };
      let result = binding.alternative(&alternative);
      assert_eq!(result.is_some(), allowed);
      if let Some(route) = result {
        assert_eq!(route.host, "bound.test");
        assert_eq!(route.port, 443);
        assert_eq!(route.protocol, protocol);
      }
    }
    // RFC 9460 §7.1.2 permits the full local ALPN list for a selected
    // transport. Exact advertisement matching is specific to Alt-Svc.
    let routes = binding.routes();
    assert_eq!(routes.len(), if no_default { 1 } else { 2 });
    assert_eq!(routes[0].protocol, WireProtocol::Http3);
    if !no_default {
      assert_eq!(routes[1].protocol, WireProtocol::Negotiated);
    }
  }
}
