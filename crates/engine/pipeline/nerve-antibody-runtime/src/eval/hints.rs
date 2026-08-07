use super::policy::InspectMode;
use crate::types::{MatchedRule, NativeRequest};
use nerve_antibody_adaptive::FeatureSnapshot;
use nerve_antibody_dsl::{apply_transforms_into, Transform};
use nerve_antibody_dsl::NativeLevel;
use nerve_antibody_metrics::{InspectPath, RisZone};
use nerve_antibody_pipeline::{is_plausible_inspect_text, RequestViews, ViewKind, ViewSlice};
use nerve_antibody_semantic::{self as semantic};

/// Nerve RIS：风险分层巡检 → (路径, zone)。
///
/// 1. 硬规则 / hard_deep → hot + Deep  
/// 2. score ≥ deep_threshold → hot + Deep（优先于 L1/L2「干净」捷径）  
/// 3. score ≥ gray_threshold 或 L2 结构异常 → gray + Fast（escalate / Shadow）  
/// 4. 仅当 score < gray 时，L1/L2/API/静态/极简 才可压成 clean + Fast  
/// 5. **否则默认 hot + Deep**（未知流量检出优先；禁止默认 Fast）
pub(super) fn resolve_ris(
    mode: InspectMode,
    static_asset: bool,
    cache_deception_probe: bool,
    hard_deep: bool,
    has_response: bool,
    decode_hint: bool,
    evasion_hint: bool,
    suspicious: bool,
    clean_json_api: bool,
    api_positive_lane: bool,
    benign_simple: bool,
    bloom_clear: bool,
    negative_hit: bool,
    structure_clean: bool,
    structure_known: bool,
    structure_anomaly: bool,
    score: f32,
    gray_threshold: f32,
    deep_threshold: f32,
) -> (InspectPath, RisZone) {
    match mode {
        InspectMode::Deep => (InspectPath::Deep, RisZone::Hot),
        InspectMode::Fast => (InspectPath::Fast, RisZone::Clean),
        InspectMode::Auto => {
            let must_hot = cache_deception_probe
                || has_response
                || decode_hint
                || evasion_hint
                || hard_deep
                || suspicious;
            if must_hot {
                return (InspectPath::Deep, RisZone::Hot);
            }
            let deep_thr = deep_threshold.max(gray_threshold);
            let gray_thr = gray_threshold.min(deep_thr);
            if score >= deep_thr {
                return (InspectPath::Deep, RisZone::Hot);
            }
            if structure_anomaly || score >= gray_thr {
                // 灰区直接 Deep（仍标 gray 供 Shadow/指标）；避免 Fast 规则集 + allow 高分冲掉检出。
                return (InspectPath::Deep, RisZone::Gray);
            }
            // 干净捷径仅静态 / 极简。L1 Bloom/负缓存不参与压 clean：
            // samples 回归里白样本 remember_clear 会污染后续黑样本指纹。
            if (static_asset && !cache_deception_probe) || benign_simple {
                return (InspectPath::Fast, RisZone::Clean);
            }
            let _ = (
                bloom_clear,
                negative_hit,
                clean_json_api,
                api_positive_lane,
                structure_clean,
                structure_known,
            );
            // 未知流量默认 Deep（hot）
            (InspectPath::Deep, RisZone::Hot)
        }
    }
}

/// 兼容旧调用：仅返回路径。
#[allow(dead_code)]
pub(super) fn resolve_inspect_path(
    mode: InspectMode,
    static_asset: bool,
    cache_deception_probe: bool,
    route_deep: bool,
    has_response: bool,
    decode_hint: bool,
    evasion_hint: bool,
    _suspicious: bool,
    clean_json_api: bool,
    api_positive_lane: bool,
    benign_simple: bool,
) -> InspectPath {
    resolve_ris(
        mode,
        static_asset,
        cache_deception_probe,
        route_deep,
        has_response,
        decode_hint,
        evasion_hint,
        false,
        clean_json_api,
        api_positive_lane,
        benign_simple,
        false,
        false,
        false,
        false,
        false,
        if route_deep { 1.0 } else { 0.0 },
        0.20,
        0.35,
    )
    .0
}

/// 极简良性请求：无 body；无 query 或短字母数字键值（无编码/引号/尖括号）。
pub(super) fn is_benign_simple_request(req: &NativeRequest) -> bool {
    if !req.body.is_empty() || req.response_body.as_ref().is_some_and(|b| !b.is_empty()) {
        return false;
    }
    if req.query.is_empty() {
        return true;
    }
    if req.query.len() > 128 {
        return false;
    }
    let q = req.query.as_bytes();
    if q.iter().any(|b| {
        matches!(
            *b,
            b'%' | b'\'' | b'"' | b'<' | b'>' | b';' | b'(' | b')' | b'|' | b'`' | b'\\' | b'/'
        )
    }) {
        return false;
    }
    q.iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'=' | b'&' | b'-' | b'_' | b'.' | b'+'))
}

/// 原始 URI/query/body 含百分号编码攻击标记（Fast 无解码时必升 deep）。
pub(super) fn raw_encoded_attack_markers(req: &NativeRequest) -> bool {
    let hay = format!("{} {} {}", req.uri, req.query, req.body).to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "%27", // '
        "%22", // "
        "%3c", // <
        "%3e", // >
        "%3b", // ;
        "%28", // (
        "%29", // )
        "%2e%2e", // ..
        "%252e", // double-encode .
        "%2500",
        "%00",
        "%0d%0a",
        "%0a",
        "%2f%2e%2e",
        "&#x",
        "\\u00",
        "\\x3c",
    ];
    MARKERS.iter().any(|m| hay.contains(m))
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

fn javascript_uri_attack_shape(lower: &str) -> bool {
    // 书名「javascript: basics…」不触发；仅 URI 载荷形
    let mut rest = lower;
    while let Some(i) = rest.find("javascript:") {
        let after = rest[i + "javascript:".len()..]
            .trim_start_matches(|c: char| c == '/' || c.is_ascii_whitespace());
        if after.starts_with("alert")
            || after.starts_with("eval")
            || after.starts_with("prompt")
            || after.starts_with("confirm")
            || after.starts_with("document.")
            || after.starts_with("window.")
            || after.starts_with("fetch(")
            || after.starts_with("setinterval")
            || after.starts_with("settimeout")
            || after.starts_with('<')
        {
            return true;
        }
        rest = &rest[i + 1..];
    }
    false
}

fn text_has_attack_shape(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    if l.contains("union select")
        || l.contains("<script")
        || l.contains("oeerror=")
        || javascript_uri_attack_shape(&l)
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

#[cfg(test)]
mod ris_tests {
    use super::resolve_ris;
    use crate::eval::policy::InspectMode;
    use nerve_antibody_metrics::{InspectPath, RisZone};

    fn auto(
        hard: bool,
        bloom: bool,
        neg: bool,
        score: f32,
    ) -> (InspectPath, RisZone) {
        resolve_ris(
            InspectMode::Auto,
            false, // static
            false, // cache_deception
            hard,
            false, // has_response
            false, // decode_hint
            false, // evasion_hint
            false, // suspicious
            false, // clean_json_api
            false, // api_positive
            false, // benign_simple
            bloom,
            neg,
            false, // structure_clean
            false, // structure_known
            false, // structure_anomaly
            score,
            0.20,
            0.35,
        )
    }

    #[test]
    fn structure_anomaly_floors_gray() {
        let (p, z) = resolve_ris(
            InspectMode::Auto,
            false,
            false,
            false,
            false,
            false,
            false,
            false, // suspicious
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true, // structure_anomaly
            0.05,
            0.20,
            0.35,
        );
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Gray);
    }

    #[test]
    fn structure_clean_cannot_override_high_score() {
        let (p, z) = resolve_ris(
            InspectMode::Auto,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true, // structure_clean
            false,
            false,
            0.50,
            0.20,
            0.35,
        );
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn structure_clean_alone_defaults_hot_deep() {
        // structure_clean 不再单独压成 clean（避免 API 形攻击漏检）
        let (p, z) = resolve_ris(
            InspectMode::Auto,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true, // structure_clean
            false,
            false,
            0.05,
            0.20,
            0.35,
        );
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn hard_is_hot_deep() {
        let (p, z) = auto(true, true, true, 0.0);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn bloom_cannot_override_high_score() {
        let (p, z) = auto(false, true, false, 0.9);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn bloom_no_longer_forces_clean() {
        let (p, z) = auto(false, true, false, 0.05);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn mid_score_is_gray_deep() {
        let (p, z) = auto(false, false, false, 0.25);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Gray);
    }

    #[test]
    fn high_score_is_hot_deep() {
        let (p, z) = auto(false, false, false, 0.40);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
    }

    #[test]
    fn unknown_low_score_defaults_hot_deep() {
        let (p, z) = auto(false, false, false, 0.05);
        assert_eq!(p, InspectPath::Deep);
        assert_eq!(z, RisZone::Hot);
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
    let mut xss_kw = [
        "<script",
        "oeerror=",
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
    if javascript_uri_attack_shape(&lower) {
        xss_kw = xss_kw.saturating_add(1);
    }
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
