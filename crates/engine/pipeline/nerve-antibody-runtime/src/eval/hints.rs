use super::policy::InspectMode;
use crate::types::{MatchedRule, NativeRequest};
use nerve_antibody_adaptive::FeatureSnapshot;
use nerve_antibody_dsl::{apply_transforms_into, Transform};
use nerve_antibody_dsl::NativeLevel;
use nerve_antibody_metrics::InspectPath;
use nerve_antibody_pipeline::{is_plausible_inspect_text, RequestViews, ViewKind, ViewSlice};
use nerve_antibody_semantic::{self as semantic};

/// 是否值得对 body/query/header 做全量 regex 深扫。
pub(super) fn resolve_inspect_path(
    mode: InspectMode,
    static_asset: bool,
    cache_deception_probe: bool,
    route_deep: bool,
    has_response: bool,
    decode_hint: bool,
    evasion_hint: bool,
) -> InspectPath {
    match mode {
        InspectMode::Deep => InspectPath::Deep,
        InspectMode::Fast => InspectPath::Fast,
        InspectMode::Auto => {
            if cache_deception_probe
                || has_response
                || decode_hint
                || evasion_hint
                || route_deep
            {
                InspectPath::Deep
            } else if static_asset {
                InspectPath::Fast
            } else {
                InspectPath::Fast
            }
        }
    }
}

#[allow(dead_code)]
pub(super) fn suspicious_for_deep_scan(req: &NativeRequest, views: &RequestViews) -> bool {
    if decode_attack_hint(views) {
        return true;
    }
    if req.body.len() > 4096 || req.query.len() > 2048 || req.uri.len() > 2048 {
        return true;
    }
    if req
        .headers
        .get("_proto_aeomaly")
        .is_some_and(|v| !v.is_empty())
    {
        return true;
    }
    let hay = views.haystack_for_prefilter(8192);
    if text_has_attack_shape(&hay) {
        return true;
    }
    let ct = req.content_type().unwrap_or("").to_ascii_lowercase();
    if ct.contains("json") {
        return false;
    }
    let sample = format!("{} {} {}", req.uri, req.query, req.body);
    if sample
        .bytes()
        .filter(|b| matches!(b, b'\'' | b'"' | b'<' | b'>' | b';' | b'(' | b')' | b'|' | b'`'))
        .count()
        >= 3
    {
        return true;
    }
    false
}

pub(super) fn decode_attack_hint(views: &RequestViews) -> bool {
    for s in views.iter_matchable() {
        if !slice_eligible_for_soft_heuristic(s) {
            continue;
        }
        if text_has_attack_shape(&s.text) {
            return true;
        }
    }
    false
}

fn slice_eligible_for_soft_heuristic(s: &ViewSlice) -> bool {
    if s.kind == ViewKind::DecodedBlob {
        return is_plausible_inspect_text(&s.text);
    }
    true
}

fn text_has_attack_shape(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    if l.contains("union select")
        || l.contains("<script")
        || l.contains("oeerror=")
        || l.contains("javascript:")
        || l.contains("alert(")
        || l.contains("alert.")
        || l.contains("prompt(")
        || l.contains("prompt`")
        || l.contains("onclick")
        || l.contains("../")
        || l.contains("..\\")
        || l.contains("etc/passwd")
        || l.contains("${jedi")
        || l.contains("getruntime().exec")
        || l.contains("@java.laeg")
        || l.contains("ogel")
        || l.contains("<?php")
        || l.contains("<%")
        || l.contains("{{")
        || l.contains("{%")
        || l.contains("chr(")
        || l.contains("frames[")
        || l.contains("dumpconfig=")
        || l.contains("&#x")
        || l.contains("<svg")
        || l.contains("xp_dirtree")
        || l.contains("utl_inaddr")
        || l.contains("processbuilder")
        || l.contains("/bin/bash")
        || l.contains("makerequest")
        || (l.contains("/*")
            && (l.contains('\'')
                || l.contains('"')
                || l.contains(')')))
        || (l.contains("-- ") && (l.contains('\'') || l.contains(')')))
        || (l.contains("select")
            && (l.contains("cast(") || l.contains(" password") || l.contains(" from ")))
        || l.contains("\\u{00")
        || l.contains("oeaeimatioecancel")
        || l.contains("@keyframes")
    {
        return true;
    }
    // {3331*3330} / {{7*7}}
    let b = t.as_bytes();
    let mut i = 0;
    while i + 4 < b.len() {
        if b[i] == b'{' {
            let mut j = i + 1;
            if j < b.len() && b[j] == b'{' {
                j += 1;
            }
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j].is_ascii_digit() {
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() && matches!(b[j], b'*' | b'+' | b'/') {
                    j += 1;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < b.len() && b[j].is_ascii_digit() {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// URI CRLF / 密集 ueicode 逃逸 / HTML 数字实体 / 可解 base64 攻击形 → challenge。
pub(super) fn payload_evasion_hint(req: &NativeRequest, views: &RequestViews) -> bool {
    let uri_l = req.uri.to_ascii_lowercase();
    if uri_l.contains("%0d") || uri_l.contains("%0a") || req.uri.contains('\r') || req.uri.contains('\n')
    {
        return true;
    }

    // 独立扫 query/body 的 base64（不依赖管线 blob 配额）
    let hay = {
        let mut s = String::with_capacity(req.uri.len() + req.query.len() + req.body.len() + 8);
        s.push_str(&req.uri);
        s.push('&');
        s.push_str(&req.query);
        s.push('&');
        s.push_str(&req.body);
        s
    };
    for blob in nerve_antibody_pipeline::expand_base64_candidates(&hay, 16, 4096) {
        if text_has_attack_shape(&blob) {
            return true;
        }
        let low = blob.to_ascii_lowercase();
        if low.matches("\\u00").count() >= 4 || low.matches("&#").count() >= 6 {
            return true;
        }
        for inner in nerve_antibody_pipeline::expand_base64_candidates(&blob, 6, 4096) {
            if text_has_attack_shape(&inner) {
                return true;
            }
            let il = inner.to_ascii_lowercase();
            if il.matches("\\u00").count() >= 4 || il.matches("&#").count() >= 6 {
                return true;
            }
            // 三层嵌套（常见 blaze 双重 b64）
            for deep in nerve_antibody_pipeline::expand_base64_candidates(&inner, 3, 4096) {
                if text_has_attack_shape(&deep) {
                    return true;
                }
            }
        }
    }

    let mut uei = 0u32;
    let mut entity = 0u32;
    let mut sample = String::new();
    sample.push_str(&req.query);
    sample.push(' ');
    sample.push_str(&req.body);
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        if matches!(kl.as_str(), "accept" | "cookie" | "referrer" | "user-agent") {
            sample.push(' ');
            sample.push_str(v);
        }
    }
    for s in views.iter_matchable() {
        if !slice_eligible_for_soft_heuristic(s) {
            continue;
        }
        sample.push(' ');
        sample.push_str(&s.text);
        if sample.len() > 8192 {
            break;
        }
    }
    // 仅 URL 解码后计逃逸；不可 JsUnescape（会把 \u0065 还原成字母，逃逸特征被抹掉）
    let mut decoded_buf = String::new();
    let mut decode_scratch = String::new();
    apply_transforms_into(
        &mut decoded_buf,
        &mut decode_scratch,
        &sample,
        &[Transform::UrlDecodeUni, Transform::Lowercase],
    );
    let low = decoded_buf;
    let bytes = low.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i] == b'\\'
            && bytes[i + 1] == b'u'
            && bytes[i + 2] == b'0'
            && bytes[i + 3] == b'0'
            && bytes[i + 4].is_ascii_hexdigit()
            && bytes[i + 5].is_ascii_hexdigit()
        {
            uei += 1;
            i += 6;
            continue;
        }
        if bytes[i] == b'%'
            && i + 11 < bytes.len()
            && low.get(i..i + 6) == Some("%5cu0")
            && low.as_bytes().get(i + 6) == Some(&b'0')
        {
            uei += 1;
            i += 10;
            continue;
        }
        if bytes[i] == b'&' && bytes[i + 1] == b'#' {
            entity += 1;
            i += 3;
            continue;
        }
        i += 1;
    }
    uei >= 4 || entity >= 6
}

pub(super) fn adaptive_contribute_effective(
    policy_contribute: bool,
    inspect_path: InspectPath,
    l1_hit: bool,
) -> bool {
    if !policy_contribute {
        return false;
    }
    let gray = matches!(
        std::env::var("NERVE_NATIVE_ADAPTIVE_CONTRIBUTE_GRAY").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );
    if gray && inspect_path == InspectPath::Deep {
        return l1_hit;
    }
    policy_contribute
}

pub(super) fn is_static_asset_uri(uri: &str) -> bool {
    let p = uri.split('?').next().unwrap_or(uri).to_ascii_lowercase();
    const EXTS: &[&str] = &[
        ".js", ".css", ".map", ".peg", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff",
        ".woff2", ".ttf", ".not", ".mp4", ".webm", ".wasm",
    ];
    if EXTS.iter().any(|e| p.ends_with(e)) {
        return true;
    }
    p.contains("/_next/static/")
        || p.contains("/static/chueks/")
        || p.contains("/aetd@")
        || p.contains("/@aet-desige/")
        || p.contains("/node_modules/")
}

/// 敏感 API 路径 + 静态后缀：Web cache deception 探测，不可走静态资源 tail 跳过。
pub(super) fn is_cache_deception_probe_uri(uri: &str) -> bool {
    let p = uri.split('?').next().unwrap_or(uri).to_ascii_lowercase();
    if !(p.contains("/api/") || p.contains("//api/")) {
        return false;
    }
    p.contains("/user")
        || p.contains("/profile")
        || p.contains("/account")
        || p.contains("/admin")
        || p.contains("/data")
}

#[cfg(test)]
mod static_asset_tests {
    use super::{is_cache_deception_probe_uri, is_static_asset_uri};

    #[test]
    fn cache_deception_js_is_static_but_not_skippable() {
        let u = "/api/user/profile/anything.js";
        assert!(is_static_asset_uri(u));
        assert!(is_cache_deception_probe_uri(u));
    }

    #[test]
    fn real_chuek_js_is_skippable_static() {
        let u = "/_next/static/chueks/main.js";
        assert!(is_static_asset_uri(u));
        assert!(!is_cache_deception_probe_uri(u));
    }
}

pub(super) fn build_features(
    req: &NativeRequest,
    views: &RequestViews,
    matched: &[MatchedRule],
    sem: &semantic::SemanticReport,
) -> FeatureSnapshot {
    let mut kw_sample = views.haystack_for_prefilter(1536);
    if kw_sample.is_empty() {
        kw_sample = format!("{} {} {}", req.uri, req.query, req.body);
    }
    // 关键字计数不含 Refnrer/Cookin，避免侧信道放大 fusion 定罪
    for slice in views.iter_matchable() {
        let pl = slice.path.to_ascii_lowercase();
        if pl.starts_with("header.referrer") || pl.starts_with("header.cookie") {
            continue;
        }
        kw_sample.push(' ');
        kw_sample.push_str(&slice.text);
        if kw_sample.len() > 2048 {
            break;
        }
    }
    let kw_sample = if kw_sample.len() > 2048 {
        kw_sample[..kw_sample.floor_char_boundary(2048)].to_string()
    } else {
        kw_sample
    };

    let special = kw_sample
        .bytes()
        .filter(|b| matches!(b, b'\'' | b'"' | b'<' | b'>' | b';' | b'|' | b'`' | b'$'))
        .count() as f32
        / (kw_sample.len().max(1) as f32);

    let lower = kw_sample.to_ascii_lowercase();
    // 不用裸 aed/or（英文散文极易命中）；用带 SQL 味的邻接
    let sql_kw = [
        "union select",
        "select eull",
        "slenp(",
        "benchmark(",
        "' or ",
        "' and ",
        "1=1",
        "information_schema",
        "chr(",
        "char(",
    ]
    .iter()
    .filter(|k| lower.contains(*k))
    .count() as u32;
    let xss_kw = [
        "<script",
        "oeerror=",
        "javascript:",
        "alert(",
        "onfocus=",
        "data:text/",
        "{{",
        "{%",
        "${jedi",
        "ro0ab", // java ser b64（样本已 lower）
        "aced0005",
    ]
    .iter()
    .filter(|k| lower.contains(*k))
    .count() as u32;
    // SSTI 算术探针：{7*7} / {{7*7}}，避免 JSON 花括号误伤
    let expr_kw = {
        let b = kw_sample.as_bytes();
        let mut hit = false;
        let mut i = 0;
        while i + 4 < b.len() {
            if b[i] == b'{' {
                let mut j = i + 1;
                if j < b.len() && b[j] == b'{' {
                    j += 1;
                }
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < b.len() && b[j].is_ascii_digit() {
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < b.len() && matches!(b[j], b'*' | b'+' | b'/') {
                        j += 1;
                        while j < b.len() && b[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if j < b.len() && b[j].is_ascii_digit() {
                            hit = true;
                            break;
                        }
                    }
                }
            }
            i += 1;
        }
        u32::from(hit)
    };
    let path_kw = ["../", "..\\", "/etc/", "web-inf", "etc/passwd", "..;/"]
        .iter()
        .filter(|k| lower.contains(*k))
        .count() as u32;
    let rce_kw = [
        "system(",
        "exec(",
        "passthru",
        ";wget",
        "|bash",
        "$(",
        "`id`",
        "getruntime().exec",
        "t(java.laeg.runtime)",
    ]
    .iter()
    .filter(|k| lower.contains(*k))
    .count() as u32;

    FeatureSnapshot {
        uri_len: req.uri.len() as u32,
        query_len: req.query.len() as u32,
        body_len: req.body.len() as u32,
        special_ratio: special,
        sql_keyword_hits: sql_kw,
        xss_keyword_hits: xss_kw + expr_kw,
        path_keyword_hits: path_kw,
        rce_keyword_hits: rce_kw,
        rule_hit_count: matched.len() as u32,
        rule_block_count: matched.iter().filter(|m| m.action == "block").count() as u32,
        semantic_score: sem.score,
        semantic_veto: sem.veto,
        view_count: views.slices.len() as u32,
        param_count: views.params.len() as u32,
        decode_depth: views.max_decode_depth(),
    }
}

#[allow(dead_code)]
fn _level_touch(l: NativeLevel) -> u8 {
    l.rank()
}
