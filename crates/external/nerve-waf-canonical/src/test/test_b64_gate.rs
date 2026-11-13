//! Tests extracted from `b64_gate/b64_gate.rs`.

use crate::b64_gate::*;

#[test]
fn skips_plain_query() {
    assert!(!text_may_contain_b64_payload(
        "tenant=coretest1&mchOrderNo=M1902534480440528898"
    ));
}

#[test]
fn detects_embedded_b64() {
    assert!(text_may_contain_b64_payload("x=PGlmcmFtZQ=="));
    assert!(text_may_contain_b64_payload("name=PGlmcmFtZQ==&x=1"));
}
