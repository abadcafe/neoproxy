use hickory_resolver::proto::rr::Name;
use hickory_resolver::proto::rr::rdata::svcb::{
  Alpn, Mandatory, SVCB, SvcParamKey, SvcParamValue,
};

use super::dns_https::service_routes;
use super::origin::{Origin, WireProtocol};

fn origin() -> Origin {
  Origin::from_uri(&"https://example.com:8443/".parse().unwrap())
    .unwrap()
}

#[test]
fn test_service_routes_selects_supported_transports_and_target_port() {
  let record = SVCB::new(
    1,
    Name::from_ascii("alt.example.").unwrap(),
    vec![
      (
        SvcParamKey::Alpn,
        SvcParamValue::Alpn(Alpn(vec!["h2".into(), "h3".into()])),
      ),
      (SvcParamKey::Port, SvcParamValue::Port(9443)),
    ],
  );
  let routes = service_routes(&record, &origin(), "example.com");
  assert_eq!(routes.len(), 2);
  assert_eq!(routes[0].protocol, WireProtocol::Http3);
  assert_eq!(routes[1].protocol, WireProtocol::Negotiated);
  assert_eq!(routes[0].host, "alt.example");
  assert_eq!(routes[0].port, 9443);
}

#[test]
fn test_service_routes_uses_default_origin_and_default_alpn() {
  let record = SVCB::new(1, Name::root(), vec![]);
  let routes = service_routes(&record, &origin(), "example.com");
  assert_eq!(routes.len(), 1);
  assert_eq!(routes[0].host, "example.com");
  assert_eq!(routes[0].port, 8443);
}

#[test]
fn test_service_routes_honors_no_default_and_mandatory_keys() {
  let mut params = vec![
    (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["h3".into()]))),
    (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
  ];
  let record = SVCB::new(1, Name::root(), params.clone());
  assert_eq!(
    service_routes(&record, &origin(), "example.com").len(),
    1
  );
  params.insert(
    0,
    (
      SvcParamKey::Mandatory,
      SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Unknown(
        65400,
      )])),
    ),
  );
  assert!(
    service_routes(
      &SVCB::new(1, Name::root(), params),
      &origin(),
      "example.com"
    )
    .is_empty()
  );
  assert!(
    service_routes(
      &SVCB::new(
        1,
        Name::root(),
        vec![(
          SvcParamKey::NoDefaultAlpn,
          SvcParamValue::NoDefaultAlpn
        )]
      ),
      &origin(),
      "example.com"
    )
    .is_empty()
  );
}

#[test]
fn test_service_routes_root_target_uses_record_owner_after_alias() {
  let record = SVCB::new(1, Name::root(), vec![]);
  let routes = service_routes(&record, &origin(), "alias.example.");
  assert_eq!(routes[0].host, "alias.example");
}
