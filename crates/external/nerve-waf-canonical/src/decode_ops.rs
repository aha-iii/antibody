//! HTTP payload decode/normalize primitives (shared by Antibody DSL and Semantic).

/// Single-step decode op (1:1 with DSL `Transform`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeOp {
    Lowercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    StripNull,
    JsUnescape,
    HtmlNumericDecode,
}

/// Stage-0 shallow canonical: single URL-decode + lowercase.
pub fn canonical_shallow(input: &str) -> String {
    url_decode_uni(input, 1).to_ascii_lowercase()
}

pub fn apply_op(input: &str, op: DecodeOp) -> String {
    match op {
        DecodeOp::Lowercase => input.to_ascii_lowercase(),
        DecodeOp::UrlDecode => url_decode(input),
        DecodeOp::UrlDecodeUni => url_decode_uni(input, 3),
        DecodeOp::HtmlEntityDecode => html_entity_decode(input),
        DecodeOp::StripNull => strip_null(input),
        DecodeOp::JsUnescape => js_unescape(input),
        DecodeOp::HtmlNumericDecode => html_numeric_decode(input),
    }
}

pub fn strip_null(s: &str) -> String {
    s.replace('\0', "")
}

/// Iterative URL-decode until stable or `max_rounds`.
pub fn url_decode_uni(s: &str, max_rounds: usize) -> String {
    let mut cur = s.to_string();
    for _ in 0..max_rounds {
        let next = url_decode(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Percent URL-decode; keep illegal `%` sequences as-is. `+` means space.
pub fn url_decode(s: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 1 < b.len() {
            if (b[i + 1] == b'u' || b[i + 1] == b'U') && i + 5 < b.len() {
                let ok = (0..4).all(|k| from_hex(b[i + 2 + k]).is_some());
                if ok {
                    if let Some(hex) = ascii_digits(b, i + 2, i + 6) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                let mut buf = [0u8; 4];
                                let enc = ch.encode_utf8(&mut buf);
                                bytes.extend_from_slice(enc.as_bytes());
                                i += 6;
                                continue;
                            }
                        }
                    }
                }
            }
            if i + 2 < b.len() {
                if let (Some(h), Some(l)) = (from_hex(b[i + 1]), from_hex(b[i + 2])) {
                    bytes.push(h << 4 | l);
                    i += 3;
                    continue;
                }
            }
        }
        if b[i] == b'+' {
            bytes.push(b' ');
            i += 1;
        } else {
            let start = i;
            i = push_utf8_char_idx(s, b, i);
            bytes.extend_from_slice(&b[start..i]);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn push_utf8_char_idx(s: &str, bytes: &[u8], i: usize) -> usize {
    if i >= bytes.len() {
        return i;
    }
    if s.is_char_boundary(i) {
        if let Some(ch) = s[i..].chars().next() {
            return i + ch.len_utf8();
        }
    }
    i + 1
}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn push_byte_as_char(out: &mut String, b: u8) {
    out.push(b as char);
}

fn push_utf8_char(s: &str, bytes: &[u8], i: usize, out: &mut String) -> usize {
    if i >= bytes.len() {
        return i;
    }
    if s.is_char_boundary(i) {
        if let Some(ch) = s[i..].chars().next() {
            out.push(ch);
            return i + ch.len_utf8();
        }
    }
    out.push('\u{FFFD}');
    i + 1
}

pub fn html_entity_decode(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn ascii_digits(bytes: &[u8], start: usize, end: usize) -> Option<&str> {
    if end > bytes.len() || start >= end {
        return None;
    }
    let slice = &bytes[start..end];
    if !slice.is_ascii() {
        return None;
    }
    std::str::from_utf8(slice).ok()
}

pub fn html_numeric_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 3 < bytes.len() && bytes[i + 1] == b'#' {
            let hex = bytes[i + 2] == b'x' || bytes[i + 2] == b'X';
            let start = if hex { i + 3 } else { i + 2 };
            let mut j = start;
            while j < bytes.len() && j - start < 6 {
                let c = bytes[j];
                let ok = if hex {
                    from_hex(c).is_some()
                } else {
                    c.is_ascii_digit()
                };
                if !ok {
                    break;
                }
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b';' {
                if let Some(num) = ascii_digits(bytes, start, j) {
                    let code = if hex {
                        u32::from_str_radix(num, 16).ok()
                    } else {
                        num.parse::<u32>().ok()
                    };
                    if let Some(cp) = code {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i = j + 1;
                            continue;
                        }
                    }
                }
            }
        }
        i = push_utf8_char(s, bytes, i, &mut out);
    }
    out
}

pub fn js_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let n = bytes[i + 1];
            if (n == b'x' || n == b'X') && i + 3 < bytes.len() {
                if let (Some(h), Some(l)) = (from_hex(bytes[i + 2]), from_hex(bytes[i + 3])) {
                    push_byte_as_char(&mut out, h << 4 | l);
                    i += 4;
                    continue;
                }
            }
            if n == b'u' && i + 3 < bytes.len() && bytes[i + 2] == b'{' {
                let mut j = i + 3;
                while j < bytes.len() && j - (i + 3) < 6 && from_hex(bytes[j]).is_some() {
                    j += 1;
                }
                if j > i + 3 && j < bytes.len() && bytes[j] == b'}' {
                    if let Some(hex) = ascii_digits(bytes, i + 3, j) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                i = j + 1;
                                continue;
                            }
                        }
                    }
                }
            }
            if n == b'u' && i + 5 < bytes.len() {
                let ok = (0..4).all(|k| from_hex(bytes[i + 2 + k]).is_some());
                if ok {
                    if let Some(hex) = ascii_digits(bytes, i + 2, i + 6) {
                        if let Ok(cp) = u32::from_str_radix(hex, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                i += 6;
                                continue;
                            }
                        }
                    }
                }
            }
            if (b'0'..=b'7').contains(&n) {
                let mut j = i + 1;
                while j < bytes.len() && j - (i + 1) < 3 && (b'0'..=b'7').contains(&bytes[j]) {
                    j += 1;
                }
                if j > i + 1 {
                    if let Some(oct) = ascii_digits(bytes, i + 1, j) {
                        if let Ok(cp) = u32::from_str_radix(oct, 8) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                i = j;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        i = push_utf8_char(s, bytes, i, &mut out);
    }
    out
}
