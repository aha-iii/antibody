//! Decode-view plausibility: separate real encoded payloads from high-entropy API signatures/IDs.

/// Whether to try Base64 on this token (shape only; independent of param name).
pub fn is_plausible_b64_candidate(tok: &str) -> bool {
    let t = tok.trim_end_matches('=');
    if t.is_empty() {
        return false;
    }
    if t.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if t.len() >= 32 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    if t.len() >= 10 {
        let b = t.as_bytes();
        if b[0].is_ascii_uppercase() && b[1..].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    if !t.contains('+')
        && !t.contains('/')
        && !t.ends_with('=')
        && t.len() >= 8
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return false;
    }
    true
}

/// Whether decode result looks like readable text payload vs random bytes from hex/b64 mis-decode.
pub fn is_plausible_decoded_text(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let s = match std::str::from_utf8(bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if !is_plausible_inspect_text(s) {
        return false;
    }
    let n = bytes.len().min(4096);
    let mut printable = 0usize;
    for &b in bytes.iter().take(n) {
        if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            printable += 1;
        }
    }
    (printable as f32 / n as f32) >= 0.85
}

/// Whether to run attack-shape heuristics on decode view / soft signals.
pub fn is_plausible_inspect_text(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let n = bytes.len().min(8192);
    let mut ctrl = 0usize;
    let mut backtick = 0usize;
    for &b in bytes.iter().take(n) {
        if (b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t')) || b == 0x7f {
            ctrl += 1;
        }
        if b == b'`' {
            backtick += 1;
        }
    }
    if ctrl * 20 > n {
        return false;
    }
    if backtick >= 2 {
        return false;
    }
    true
}
