//! Stage-0 深路径路由门闩：轻量特征 + 线性打分（<50µs 目标）。
//!
//! 只决定 fast/deep，不参与 block 裁决；权重可由 pack / JSON 校准。

use crate::types::NativeRequest;
use nerve_antibody_pipeline::RequestViews;
use std::collections::HashMap;

/// Learned Fast Filter 特征维度（bench 可训线性/逻辑回归）。
pub const ROUTE_FEATURE_DIM: usize = 20;

/// 路由门闩配置（来自 pack `[policy.inspect.route_gate]`）。
#[derive(Debug, Clone)]
pub struct RouteGateConfig {
    pub enabled: bool,
    /// 线性分 ≥ 此值 → deep（0.0–1.0）。
    pub deep_threshold: f32,
    /// 硬触发：decode/evasion hint 仍强制 deep。
    pub hard_decode_hint: bool,
    pub weights: RouteGateWeights,
}

impl Default for RouteGateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deep_threshold: 0.38,
            hard_decode_hint: true,
            weights: RouteGateWeights::builtin(),
        }
    }
}

/// 线性模型权重（对应 [`feature_vector`] 20 维）。
#[derive(Debug, Clone)]
pub struct RouteGateWeights {
    pub bias: f32,
    pub w: [f32; ROUTE_FEATURE_DIM],
}

impl RouteGateWeights {
    /// 与历史硬编码等价的默认权重。
    pub fn builtin() -> Self {
        let mut w = [0.0f32; ROUTE_FEATURE_DIM];
        w[0] = 0.42; // attack_shape
        w[1] = 0.32; // operator_hits_norm (×1 即 cap 0.32 at 4 hits)
        w[2] = 0.48; // quote_ratio (×4 cap 0.12)
        w[3] = 0.30; // special_ratio (×3 cap 0.10)
        w[4] = 0.08; // url_encoded_ratio
        w[5] = 0.015; // entropy_norm (×4 cap ~0.06 at 4.2 bits)
        w[6] = 1.0; // large_body_soft
        w[7] = 0.5; // proto_anomaly
        w[8] = 0.04; // method_post
        w[9] = 0.02; // has_query
        w[10] = 0.03; // body_kb_log
        w[11] = 0.02; // header_count_norm
        w[12] = 0.02; // cookie_present
        w[13] = 0.03; // json_ct
        w[14] = 0.02; // multipart_ct
        w[15] = 0.06; // double_encode
        w[16] = 0.08; // sql_comment
        w[17] = 0.10; // xss_angle
        w[18] = 0.12; // path_traversal
        w[19] = 0.01; // sample_len_norm
        Self { bias: 0.0, w }
    }

    /// 从 JSON 加载：`{ "bias": 0, "weights": { "attack_shape": 0.42, ... } }` 或 `"weights": [..20]`。
    pub fn from_json(text: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default)]
            bias: f32,
            #[serde(default)]
            weights: serde_json::Value,
        }
        let raw: Raw = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let mut w = RouteGateWeights::builtin().w;
        match raw.weights {
            serde_json::Value::Array(arr) => {
                for (i, v) in arr.into_iter().take(ROUTE_FEATURE_DIM).enumerate() {
                    if let Some(f) = v.as_f64() {
                        w[i] = f as f32;
                    }
                }
            }
            serde_json::Value::Object(map) => {
                let names = feature_names();
                for (i, name) in names.iter().enumerate() {
                    if let Some(v) = map.get(*name).and_then(|x| x.as_f64()) {
                        w[i] = v as f32;
                    }
                }
            }
            _ => {}
        }
        Ok(Self { bias: raw.bias, w })
    }

    /// 从 pack inline `[policy.inspect.route_gate.weights]` 键值覆盖。
    pub fn apply_named_overrides(&mut self, map: &HashMap<String, f32>) {
        for (i, name) in feature_names().iter().enumerate() {
            if let Some(v) = map.get(*name) {
                self.w[i] = *v;
            }
        }
    }
}

pub fn feature_names() -> [&'static str; ROUTE_FEATURE_DIM] {
    [
        "attack_shape",
        "operator_hits_norm",
        "quote_ratio",
        "special_ratio",
        "url_encoded_ratio",
        "entropy_norm",
        "large_body_soft",
        "proto_anomaly",
        "method_post",
        "has_query",
        "body_kb_log",
        "header_count_norm",
        "cookie_present",
        "json_ct",
        "multipart_ct",
        "double_encode",
        "sql_comment",
        "xss_angle",
        "path_traversal",
        "sample_len_norm",
    ]
}

/// 路由特征（白盒可解释）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteFeatures {
    pub sample_len: u32,
    pub quote_ratio: f32,
    pub special_ratio: f32,
    pub url_encoded_ratio: f32,
    pub operator_hits: u32,
    pub attack_shape: bool,
    pub entropy_bits: f32,
    pub large_body_soft: f32,
    pub proto_anomaly: bool,
    pub method_post: bool,
    pub has_query: bool,
    pub body_kb_log: f32,
    pub header_count_norm: f32,
    pub cookie_present: bool,
    pub json_ct: bool,
    pub multipart_ct: bool,
    pub double_encode: bool,
    pub sql_comment: bool,
    pub xss_angle: bool,
    pub path_traversal: bool,
}

/// 路由打分结果。
#[derive(Debug, Clone, Copy)]
pub struct RouteDecision {
    pub score: f32,
    pub features: RouteFeatures,
    pub route_deep: bool,
    /// 干净 JSON API：不应因 Fast 池超时升到 Deep（避免 +1s 级延迟）。
    pub clean_json_api: bool,
    /// OpenAPI/REST JSON 正向快通道（L0–L1，跳过 tail regex 深扫）。
    pub api_positive_lane: bool,
}

/// 从请求抽取路由样本（不做完整 DecodePipeline）。
pub fn route_sample(req: &NativeRequest, max_total: usize) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push(req.uri.as_str());
    if !req.query.is_empty() {
        parts.push(req.query.as_str());
    }
    if !req.body.is_empty() {
        let take = req.body.len().min(max_total / 2);
        parts.push(truncate_utf8(&req.body, take));
    }
    if let Some(ct) = req.content_type() {
        parts.push(ct);
    }
    let joined = parts.join("\n");
    truncate_utf8_owned(&joined, max_total)
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn truncate_utf8_owned(s: &str, max_bytes: usize) -> String {
    truncate_utf8(s, max_bytes).to_string()
}

/// 计算特征（ASCII 归一化样本）。
pub fn extract_features(req: &NativeRequest, sample: &str) -> RouteFeatures {
    let lower = sample.to_ascii_lowercase();
    let len = lower.len().max(1) as u32;

    let mut quotes = 0u32;
    let mut special = 0u32;
    let mut url_enc = 0u32;
    let mut byte_freq = [0u32; 256];
    for &b in lower.as_bytes() {
        byte_freq[b as usize] = byte_freq[b as usize].saturating_add(1);
        match b {
            b'\'' | b'"' => quotes += 1,
            b'<' | b'>' | b';' | b'(' | b')' | b'|' | b'`' | b'\\' => special += 1,
            b'%' if lower.as_bytes().windows(3).any(|w| w == b"%25") => url_enc += 1,
            _ => {}
        }
    }
    if lower.contains("%3c") || lower.contains("%3e") || lower.contains("%27") {
        url_enc = url_enc.saturating_add(1);
    }

    let operator_hits = count_substr(&lower, " union ")
        + count_substr(&lower, " select ")
        + count_substr(&lower, " or 1")
        + count_substr(&lower, " and 1")
        + count_substr(&lower, "<script")
        + count_substr(&lower, "javascript:")
        + count_substr(&lower, "../")
        + count_substr(&lower, "%2e%2e");

    let entropy_bits = shannon_entropy(&byte_freq, len as usize);

    let body_kb = req.body.len() as f32 / 1024.0;
    let large_body_soft = if body_kb <= 4.0 {
        0.0
    } else if body_kb >= 64.0 {
        0.25
    } else {
        (body_kb - 4.0) / 240.0
    };

    let ct = req.content_type().unwrap_or("").to_ascii_lowercase();
    RouteFeatures {
        sample_len: len,
        quote_ratio: quotes as f32 / len as f32,
        special_ratio: special as f32 / len as f32,
        url_encoded_ratio: url_enc as f32 / len as f32,
        operator_hits: operator_hits.min(8),
        attack_shape: text_has_attack_shape(&lower),
        entropy_bits,
        large_body_soft,
        proto_anomaly: req
            .headers
            .get("_proto_anomaly")
            .is_some_and(|v| !v.is_empty()),
        method_post: req.method.eq_ignore_ascii_case("POST"),
        has_query: !req.query.is_empty(),
        body_kb_log: (body_kb + 1.0).log2() / 10.0,
        header_count_norm: (req.headers.len() as f32 / 32.0).min(1.0),
        cookie_present: req.headers.keys().any(|k| k.eq_ignore_ascii_case("cookie")),
        json_ct: ct.contains("json"),
        multipart_ct: ct.contains("multipart"),
        double_encode: lower.contains("%25"),
        sql_comment: lower.contains("--") || lower.contains("#"),
        xss_angle: lower.contains('<') || lower.contains("%3c"),
        path_traversal: lower.contains("../") || lower.contains("%2e%2e"),
    }
}

/// 20 维特征向量（归一化到约 0–1）。
pub fn feature_vector(f: &RouteFeatures) -> [f32; ROUTE_FEATURE_DIM] {
    [
        f32::from(f.attack_shape),
        f.operator_hits as f32 / 8.0,
        f.quote_ratio.min(0.25) * 4.0,
        f.special_ratio.min(0.04) * 3.0,
        if f.url_encoded_ratio > 0.005 { 1.0 } else { 0.0 },
        (f.entropy_bits / 8.0).min(1.0),
        f.large_body_soft,
        f32::from(f.proto_anomaly),
        f32::from(f.method_post),
        f32::from(f.has_query),
        f.body_kb_log.min(1.0),
        f.header_count_norm,
        f32::from(f.cookie_present),
        f32::from(f.json_ct),
        f32::from(f.multipart_ct),
        f32::from(f.double_encode),
        f32::from(f.sql_comment),
        f32::from(f.xss_angle),
        f32::from(f.path_traversal),
        (f.sample_len as f32 / 8192.0).min(1.0),
    ]
}

pub fn score_features(f: &RouteFeatures, weights: &RouteGateWeights) -> f32 {
    let fv = feature_vector(f);
    let mut s = weights.bias;
    for (i, v) in fv.iter().enumerate() {
        s += weights.w[i] * v;
    }
    s.clamp(0.0, 1.0)
}

/// 是否应走深路径（结合硬 hint 与门闩分）。
pub fn decide_deep(
    cfg: &RouteGateConfig,
    req: &NativeRequest,
    _views: &RequestViews,
    decode_hint: bool,
    evasion_hint: bool,
    cache_deception: bool,
    has_response: bool,
) -> RouteDecision {
    if !cfg.enabled {
        let f = extract_features(req, &route_sample(req, 12 * 1024));
        return RouteDecision {
            score: score_features(&f, &cfg.weights),
            features: f,
            route_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }

    if cache_deception || has_response {
        let f = extract_features(req, &route_sample(req, 12 * 1024));
        return RouteDecision {
            score: 1.0,
            features: f,
            route_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }
    if cfg.hard_decode_hint && (decode_hint || evasion_hint) {
        let f = extract_features(req, &route_sample(req, 12 * 1024));
        return RouteDecision {
            score: 1.0,
            features: f,
            route_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }

    let sample = route_sample(req, 12 * 1024);
    let features = extract_features(req, &sample);
    let score = score_features(&features, &cfg.weights);
    let api_lane = is_api_positive_lane(req, &features, decode_hint, evasion_hint);
    if is_clean_json_api(&features, decode_hint, evasion_hint) || api_lane {
        return RouteDecision {
            score,
            features,
            route_deep: false,
            clean_json_api: !api_lane,
            api_positive_lane: api_lane,
        };
    }
    RouteDecision {
        score,
        features,
        route_deep: score >= cfg.deep_threshold,
        clean_json_api: false,
        api_positive_lane: false,
    }
}

/// OpenAPI/REST JSON 正向快通道：已知 API 形态，仅 L0 路由 + L1 Aho，不做 tail regex 深扫。
pub fn is_api_positive_lane(
    req: &NativeRequest,
    f: &RouteFeatures,
    decode_hint: bool,
    evasion_hint: bool,
) -> bool {
    if !f.json_ct || decode_hint || evasion_hint || f.attack_shape {
        return false;
    }
    if f.operator_hits > 0 || f.path_traversal || f.xss_angle || f.sql_comment || f.double_encode {
        return false;
    }
    let method = req.method.to_ascii_uppercase();
    if !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        return false;
    }
    if req.body.len() > 65536 {
        return false;
    }
    let path = req.uri.split('?').next().unwrap_or(&req.uri);
    path.starts_with("/open/api/") || path.starts_with("/api/")
}

/// 干净 JSON API：高 quote 比来自字段分隔符，非攻击形态。
fn is_clean_json_api(f: &RouteFeatures, decode_hint: bool, evasion_hint: bool) -> bool {
    f.json_ct
        && !f.attack_shape
        && !decode_hint
        && !evasion_hint
        && f.operator_hits == 0
        && !f.path_traversal
        && !f.xss_angle
        && !f.sql_comment
        && !f.double_encode
        && f.url_encoded_ratio <= 0.005
}

fn count_substr(hay: &str, needle: &str) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    hay.match_indices(needle).count() as u32
}

fn shannon_entropy(freq: &[u32; 256], total: usize) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let t = total as f32;
    let mut h = 0.0f32;
    for &c in freq.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f32 / t;
        h -= p * p.log2();
    }
    h
}

fn text_has_attack_shape(hay: &str) -> bool {
    hay.contains("<script")
        || hay.contains("javascript:")
        || hay.contains(" onerror=")
        || hay.contains(" onload=")
        || hay.contains(" union ")
        || hay.contains("union select")
        || hay.contains("1=1")
        || hay.contains("1' or")
        || hay.contains("' or '")
        || hay.contains("../")
        || hay.contains("/etc/passwd")
        || hay.contains("eval(")
        || hay.contains("<?php")
        || hay.contains("${")
        || hay.contains("&&")
        || hay.contains("||")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_get_stays_fast() {
        let req = NativeRequest {
            method: "GET".into(),
            uri: "/api/users".into(),
            query: "page=1&size=20".into(),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(!d.route_deep, "score={}", d.score);
    }

    #[test]
    fn sqli_routes_deep() {
        let req = NativeRequest {
            method: "GET".into(),
            uri: "/x".into(),
            query: "id=1' union select null--".into(),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(d.route_deep, "score={}", d.score);
    }

    #[test]
    fn large_clean_body_not_auto_deep() {
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/upload".into(),
            body: "a".repeat(20_000),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(!d.route_deep, "large prose body should not hard-deep: {}", d.score);
    }

    #[test]
    fn json_weights_load() {
        let text = r#"{"bias":0.01,"weights":{"attack_shape":0.5,"operator_hits_norm":0.2}}"#;
        let w = RouteGateWeights::from_json(text).unwrap();
        assert!((w.bias - 0.01).abs() < 1e-5);
        assert!((w.w[0] - 0.5).abs() < 1e-5);
    }

    #[test]
    fn feature_vector_dim() {
        let f = RouteFeatures::default();
        assert_eq!(feature_vector(&f).len(), ROUTE_FEATURE_DIM);
    }

    #[test]
    fn clean_json_api_stays_fast_despite_quotes() {
        let body = r#"{"tenantCode":"test","tenantName":"平台测试","templateCode":"TCY_CODE_000001","phoneNumber":"13800138000"}"#;
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/open/api/msg/sms/v1/send".into(),
            body: body.into(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(!d.route_deep, "JSON API score={}", d.score);
        assert!(d.api_positive_lane, "SMS openapi should use api positive lane");
    }

    #[test]
    fn api_positive_lane_requires_json_post() {
        let req = NativeRequest {
            method: "GET".into(),
            uri: "/open/api/msg/sms/v1/send".into(),
            body: String::new(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(!d.api_positive_lane);
    }

    #[test]
    fn route_sample_multibyte_boundary_no_panic() {
        // 模拟 multipart 大包：字节截断点落在多字节字符中间时不 panic
        let mut body = "a".repeat(650);
        body.push('é'); // 2-byte UTF-8 at 651..653
        body.push_str("rest");
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/".into(),
            body,
            ..Default::default()
        };
        let sample = route_sample(&req, 654);
        assert!(sample.len() <= 654);
    }
}
