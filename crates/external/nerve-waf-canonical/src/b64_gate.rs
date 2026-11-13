//! Fast gate for Base64 expansion: skip regex scan when no b64 features.

use crate::plausibility::is_plausible_b64_candidate;

/// Whether text may contain base64 payloads that need expansion.
pub fn text_may_contain_b64_payload(text: &str) -> bool {
    if text.len() < 8 {
        return false;
    }
    if !(text.contains('+') || text.contains('/') || text.contains('=')) {
        return false;
    }
    for part in text.split('&') {
        if let Some((_k, val)) = part.split_once('=') {
            if candidate_looks_like_b64(val) {
                return true;
            }
        }
    }
    for tok in split_b64_tokens(text) {
        if candidate_looks_like_b64(tok) {
            return true;
        }
    }
    false
}

fn candidate_looks_like_b64(s: &str) -> bool {
    let t = s.trim();
    if t.len() < 8 {
        return false;
    }
    let has_b64_markers = t.contains('+') || t.contains('/') || t.ends_with('=');
    if !has_b64_markers {
        return false;
    }
    if !t.len().is_multiple_of(4) && !t.contains('+') && !t.contains('/') {
        return false;
    }
    is_plausible_b64_candidate(t)
}

fn split_b64_tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        !c.is_ascii_alphanumeric() && c != '+' && c != '/' && c != '-' && c != '_' && c != '='
    })
    .filter(|t| !t.is_empty())
}
