//! Base64 候选提取与解码。

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use regex::Regex;
use std::sync::OnceLock;

use crate::text_plausibility::{is_plausible_b64_candidate, is_plausible_decoded_text};

fn token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // 最短约 8：覆盖 `<iframe` / `alert(1)` 等短 XSS blob（`PGlmcmFtZQ==` 仅 12 字符）
    RE.get_or_init(|| Regex::new(r#"[A-Za-z0-9_+\-/]{8,}={0,2}"#).unwrap())
}

/// 从文本中提取并解码 base64 候选，返回解码后的 UTF-8 文本。
/// 优先长 token，避免短噪声占满配额导致真 payload 漏检。
pub fn expand_base64_candidates(hay: &str, max: usize, max_chars: usize) -> Vec<String> {
    if max == 0 || hay.is_empty() {
        return Vec::new();
    }
    let mut toks: Vec<&str> = token_re().find_iter(hay).map(|m| m.as_str()).collect();
    toks.sort_by_key(|t| std::cmp::Reverse(t.len()));
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for tok in toks {
        if out.len() >= max {
            break;
        }
        if tok.len() < 12 || tok.len() > max_chars * 2 {
            continue;
        }
        if !is_plausible_b64_candidate(tok) {
            continue;
        }
        if let Some(decoded) = try_decode_b64(tok) {
            if !is_plausible_decoded_text(&decoded) {
                continue;
            }
            let s = match String::from_utf8(decoded) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if s.len() < 4 || s.len() > max_chars {
                continue;
            }
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

fn try_decode_b64(tok: &str) -> Option<Vec<u8>> {
    let engines = [
        &STANDARD,
        &STANDARD_NO_PAD,
        &URL_SAFE,
        &URL_SAFE_NO_PAD,
    ];
    for eng in engines {
        if let Ok(v) = eng.decode(tok) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    // 补 padding 再试
    let mut padded = tok.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    for eng in [&STANDARD, &URL_SAFE] {
        if let Ok(v) = eng.decode(&padded) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_iframe_b64() {
        // <iframe
        let s = "prefix PGlmcmFtZQ== suffix";
        let v = expand_base64_candidates(s, 8, 1024);
        assert!(v.iter().any(|x| x.to_ascii_lowercase().contains("iframe")));
    }

    #[test]
    fn ignores_openapi_sign_in_query() {
        let q = "sign=05A6E5389357923F02BCC67FAA5036131ECCDC122950646D3A1178FD1F7E5976&timestamp=1785289955109";
        let v = expand_base64_candidates(q, 8, 1024);
        assert!(v.is_empty(), "hex sign and timestamp must not decode as b64 payloads");
    }
}
