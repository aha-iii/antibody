//! Tests extracted from `plausibility/plausibility.rs`.

use crate::plausibility::*;

#[test]
fn skips_api_signature_tokens() {
    assert!(!is_plausible_b64_candidate(
        "05A6E5389357923F02BCC67FAA5036131ECCDC122950646D3A1178FD1F7E5976"
    ));
    assert!(!is_plausible_b64_candidate("1785289955109"));
    assert!(!is_plausible_b64_candidate("M1902534480440528898"));
}

#[test]
fn keeps_real_b64_payloads() {
    assert!(is_plausible_b64_candidate("PGlmcmFtZQ=="));
}
