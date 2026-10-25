//! module: certificate_tests
//! responsibility: specify credential compilation and identity coverage
//! public operations: tests through cargo test
//! data entities: Fixture
//! tests: candidate loading, coverage, chain isolation and scheme
//! selection

use crate::certificate::Candidates;

struct Fixture {
  cert: String,
  key: String,
  _directory: tempfile::TempDir,
}

fn fixture(names: &[&str]) -> Fixture {
  let _ = rustls::crypto::ring::default_provider().install_default();
  let directory = tempfile::tempdir().unwrap();
  let key = rcgen::KeyPair::generate().unwrap();
  let certificate = rcgen::CertificateParams::new(
    names.iter().map(|name| name.to_string()).collect::<Vec<_>>(),
  )
  .unwrap()
  .self_signed(&key)
  .unwrap();
  let cert_path = directory.path().join("cert.pem");
  let key_path = directory.path().join("key.pem");
  std::fs::write(&cert_path, certificate.pem()).unwrap();
  std::fs::write(&key_path, key.serialize_pem()).unwrap();
  Fixture {
    cert: cert_path.to_string_lossy().into_owned(),
    key: key_path.to_string_lossy().into_owned(),
    _directory: directory,
  }
}

#[test]
fn test_validate_names_matches_exact_wildcard_case_and_root_dot() {
  let fixture = fixture(&["*.example.com", "other.test"]);
  let candidates =
    Candidates::load([(fixture.cert.as_str(), fixture.key.as_str())])
      .unwrap();
  for name in ["API.EXAMPLE.COM.", "*.example.com", "OTHER.TEST."] {
    assert!(
      candidates.validate_names(&[name.into()]).is_ok(),
      "{name}"
    );
  }
  for name in [
    "example.com",
    ".example.com",
    "nested.api.example.com",
    "*.other.test",
  ] {
    assert!(
      candidates.validate_names(&[name.into()]).is_err(),
      "{name}"
    );
  }
}

#[test]
fn test_validate_names_default_allows_extra_or_absent_dns_sans() {
  let fixture = fixture(&[]);
  let candidates =
    Candidates::load([(fixture.cert.as_str(), fixture.key.as_str())])
      .unwrap();
  assert!(candidates.validate_names(&[]).is_ok());
  assert!(candidates.validate_names(&["named.test".into()]).is_err());
}

#[test]
fn test_validate_names_does_not_import_intermediate_sans() {
  let leaf = fixture(&["leaf.test"]);
  let other = fixture(&["intermediate.test"]);
  let chain = std::fs::read_to_string(&leaf.cert).unwrap()
    + &std::fs::read_to_string(&other.cert).unwrap();
  std::fs::write(&leaf.cert, chain).unwrap();
  let candidates =
    Candidates::load([(leaf.cert.as_str(), leaf.key.as_str())])
      .unwrap();
  assert!(candidates.validate_names(&["leaf.test".into()]).is_ok());
  assert!(
    candidates.validate_names(&["intermediate.test".into()]).is_err()
  );
  let selected = candidates
    .choose(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
    .unwrap();
  assert_eq!(selected.cert.len(), 2);
}

#[test]
fn test_load_rejects_empty_malformed_and_mismatched_credentials() {
  let first = fixture(&["first.test"]);
  let second = fixture(&["second.test"]);
  assert!(
    Candidates::load([(first.cert.as_str(), second.key.as_str())])
      .is_err()
  );
  for content in [
    "",
    "not PEM",
    "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
  ] {
    std::fs::write(&first.cert, content).unwrap();
    assert!(
      Candidates::load([(first.cert.as_str(), first.key.as_str())])
        .is_err()
    );
  }
}

#[test]
fn test_load_rejects_missing_paths_and_no_candidates() {
  assert!(Candidates::load(std::iter::empty()).is_err());
  assert!(
    Candidates::load([(
      "/nonexistent/cert.pem",
      "/nonexistent/key.pem"
    )])
    .is_err()
  );
}

#[test]
fn test_choose_rejects_incompatible_signature_schemes() {
  let fixture = fixture(&["named.test"]);
  let candidates =
    Candidates::load([(fixture.cert.as_str(), fixture.key.as_str())])
      .unwrap();
  assert!(
    candidates
      .choose(&[rustls::SignatureScheme::RSA_PSS_SHA256])
      .is_none()
  );
  assert!(candidates.choose(&[]).is_none());
  assert!(
    candidates
      .choose(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
      .is_some()
  );
}
