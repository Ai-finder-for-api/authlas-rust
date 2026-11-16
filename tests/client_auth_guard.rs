//! A private_key_jwt client registered without an algorithm allow-list must be refused, even though the C wrapper now
//! accepts an absent `assertion_algs` for secret-based clients.

use authlas::oauth::client_auth::{authenticate, Method, Presented, Registered};

#[test]
fn private_key_jwt_without_algorithm_allow_list_is_refused() {
    let reg = Registered {
        client_id: "svc".into(),
        method: Method::PrivateKeyJwt,
        secret: None,
        secret_is_hash: false,
        jwk: None,
        assertion_algs: vec![],
    };
    let p = Presented::Assertion { client_id: Some("svc".into()), assertion: "a.b.c".into() };
    assert!(authenticate(&p, &reg, "https://as.example/token", None, Some(1000), None).is_err());
}

#[test]
fn secret_client_without_algorithm_list_still_authenticates() {
    let reg = Registered {
        client_id: "app".into(),
        method: Method::SecretBasic,
        secret: Some(b"s3cret".to_vec()),
        secret_is_hash: false,
        jwk: None,
        assertion_algs: vec![],
    };
    let p = Presented::Basic { client_id: "app".into(), secret: "s3cret".into() };
    assert_eq!(authenticate(&p, &reg, "https://as.example/token", None, Some(1000), None).unwrap(), "app");
}
