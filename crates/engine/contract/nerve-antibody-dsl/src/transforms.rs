//! 请求字段归一化变换（匹配前执行，顺序敏感）。

use crate::types::Transform;
use nerve_waf_canonical::{apply_op, DecodeOp};

pub fn apply_transforms(input: &str, transforms: &[Transform]) -> String {
    let mut s = input.to_string();
    for t in transforms {
        s = apply_op(&s, decode_op(*t));
    }
    s
}

/// 按 `transforms` 顺序变换 `input`，结果写入 `primary`（复用 `scratch` 缓冲）。
pub fn apply_transforms_into(
    primary: &mut String,
    scratch: &mut String,
    input: &str,
    transforms: &[Transform],
) {
    primary.clear();
    primary.push_str(input);
    if transforms.is_empty() {
        return;
    }
    for t in transforms {
        scratch.clear();
        scratch.push_str(&apply_op(primary, decode_op(*t)));
        std::mem::swap(primary, scratch);
    }
}

fn decode_op(t: Transform) -> DecodeOp {
    match t {
        Transform::Lowercase => DecodeOp::Lowercase,
        Transform::UrlDecode => DecodeOp::UrlDecode,
        Transform::UrlDecodeUni => DecodeOp::UrlDecodeUni,
        Transform::HtmlEntityDecode => DecodeOp::HtmlEntityDecode,
        Transform::StripNull => DecodeOp::StripNull,
        Transform::JsUnescape => DecodeOp::JsUnescape,
        Transform::HtmlNumericDecode => DecodeOp::HtmlNumericDecode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Transform;

    #[test]
    fn js_unescape_hex_alert() {
        let s = apply_transforms(
            r"\x61\x6c\x65\x72\x74",
            &[Transform::JsUnescape, Transform::Lowercase],
        );
        assert_eq!(s, "alert");
    }

    #[test]
    fn html_numeric_javascript() {
        let s = apply_transforms(
            "j&#x61;vascript:alert(1)",
            &[Transform::HtmlNumericDecode, Transform::Lowercase],
        );
        assert!(s.contains("javascript:alert(1)"));
    }

    #[test]
    fn url_decode_uni_handles_iis_percent_u() {
        let s = apply_transforms(
            "x%u000d%u000aSet-Cookie:a=1",
            &[Transform::UrlDecodeUni, Transform::Lowercase],
        );
        assert!(
            s.contains('\r') && s.contains('\n') && s.contains("set-cookie"),
            "got {s:?}"
        );
    }
}
