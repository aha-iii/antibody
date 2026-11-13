//! Tests extracted from `local/local.rs`.

use crate::local::*;

#[test]
fn local_token_roundtrip() {
    let auth = LocalAuth {
        jwt_secret: b"test-secret-key-at-least-32-bytes!!".to_vec(),
        token_ttl_secs: 3600,
    };
    let resp = auth.issue_token("admin", "admin").expect("issue");
    assert!(auth.validate_token(&resp.token));
    assert_eq!(resp.role, "admin");
    assert_eq!(
        auth.claims_from_token(&resp.token),
        Some(("admin".into(), "admin".into()))
    );
}
