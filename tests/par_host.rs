//! Host-backed PAR (src/oauth/par_host.rs). The test storage is a plain map, the same way a host app would keep state.

use authlas::oauth::form::Params;
use authlas::oauth::par_host::{self, PushStorage, StoredPush};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct MapStore(Mutex<HashMap<String, StoredPush>>);

impl PushStorage for MapStore {
    fn save(&self, rec: StoredPush) -> Result<(), String> {
        self.0.lock().unwrap().insert(rec.request_uri.clone(), rec);
        Ok(())
    }
    fn take(&self, request_uri: &str) -> Result<Option<StoredPush>, String> {
        Ok(self.0.lock().unwrap().remove(request_uri))
    }
}

const BODY: &str = "client_id=app&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=xyz";

#[test]
fn push_then_redeem_once() {
    let store = MapStore::default();
    let params = Params::parse(BODY).unwrap();
    let (uri, life) = par_host::push(&store, "app", &params, BODY, Some(1_000)).unwrap();
    assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(life, 60);
    let query = par_host::redeem(&store, "app", &uri, Some(1_010)).unwrap();
    assert!(query.contains("state=xyz"));
    // second use is refused: the record was removed on the first redeem
    assert!(par_host::redeem(&store, "app", &uri, Some(1_011)).is_err());
}

#[test]
fn wrong_client_cannot_redeem_and_loses_the_reference() {
    let store = MapStore::default();
    let params = Params::parse(BODY).unwrap();
    let (uri, _) = par_host::push(&store, "app", &params, BODY, Some(1_000)).unwrap();
    assert!(par_host::redeem(&store, "attacker", &uri, Some(1_001)).is_err());
    // the reference is gone even for the rightful client
    assert!(par_host::redeem(&store, "app", &uri, Some(1_002)).is_err());
}

#[test]
fn expired_reference_is_refused() {
    let store = MapStore::default();
    let params = Params::parse(BODY).unwrap();
    let (uri, _) = par_host::push(&store, "app", &params, BODY, Some(1_000)).unwrap();
    assert!(par_host::redeem(&store, "app", &uri, Some(1_000 + 61)).is_err());
}

#[test]
fn request_uri_in_a_push_is_refused() {
    let store = MapStore::default();
    let body = "client_id=app&request_uri=urn%3Aevil";
    let params = Params::parse(body).unwrap();
    assert!(par_host::push(&store, "app", &params, body, Some(1_000)).is_err());
}

#[test]
fn client_secret_is_not_stored() {
    let store = MapStore::default();
    let body = "client_id=app&client_secret=hunter2&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb";
    let params = Params::parse(body).unwrap();
    let (uri, _) = par_host::push(&store, "app", &params, body, Some(1_000)).unwrap();
    let query = par_host::redeem(&store, "app", &uri, Some(1_001)).unwrap();
    assert!(!query.contains("hunter2"), "stored query must not carry the client secret");
    assert!(!query.contains("client_secret"));
}

#[test]
fn unknown_reference_is_refused() {
    let store = MapStore::default();
    assert!(par_host::redeem(&store, "app", "urn:ietf:params:oauth:request_uri:nope", Some(1)).is_err());
    assert!(par_host::redeem(&store, "app", "https://evil.example/x", Some(1)).is_err());
}
