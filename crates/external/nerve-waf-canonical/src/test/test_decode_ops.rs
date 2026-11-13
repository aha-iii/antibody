//! Tests extracted from `decode_ops/decode_ops.rs`.

use crate::decode_ops::*;

#[test]
fn double_percent_url_path() {
    let s = url_decode_uni("/%252fetc%252fpasswd", 3);
    assert!(s.contains("/etc/passwd"), "got {s:?}");
}

#[test]
fn canonical_shallow_url_once() {
    let s = canonical_shallow("%253Cscript%253E");
    assert!(s.contains("%3cscript") || s.contains("<script"));
}

#[test]
fn url_decode_uni_handles_iis_percent_u() {
    let s = apply_op("x%u000d%u000aSet-Cookie:a=1", DecodeOp::UrlDecodeUni).to_ascii_lowercase();
    assert!(s.contains('\r') && s.contains('\n') && s.contains("set-cookie"));
}
