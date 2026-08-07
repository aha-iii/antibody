//! Stage-0 深路径路由门闩：轻量特征 + 线性打分（<50µs 目标）。
//!
//! 只决定 fast/deep，不参与 block 裁决；权重可由 pack / JSON 校准。

use crate::types::NativeRequest;
use nerve_antibody_pipeline::RequestViews;
use std::collections::HashMap;

/// Learned Fast Filter 特征维度（逻辑回归 + 可选 stump 增强）。
pub const ROUTE_FEATURE_DIM: usize = 28;

/// 路由门闩配置（来自 pack `[policy.inspect.route_gate]`）。
#[derive(Debug, Clone)]
pub struct RouteGateConfig {
    pub enabled: bool,
    /// Nerve RIS：`score ≥ deep_threshold` → hot → Deep。
    pub deep_threshold: f32,
    /// Nerve RIS：`gray_threshold ≤ score < deep_threshold` → gray → Fast(+escalate)。
    pub gray_threshold: f32,
    /// 硬触发：decode/evasion hint 仍强制 deep。
    pub hard_decode_hint: bool,
    pub weights: RouteGateWeights,
}

impl Default for RouteGateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deep_threshold: 0.35,
            gray_threshold: 0.20,
            hard_decode_hint: true,
            weights: RouteGateWeights::builtin(),
        }
    }
}

/// 单特征 stump（轻量 GBDT 一阶：AdaBoost 式残差桩）。
#[derive(Debug, Clone, Copy)]
pub struct RouteStump {
    pub feature: u16,
    pub threshold: f32,
    pub left: f32,
    pub right: f32,
    pub alpha: f32,
}

/// 线性 + 可选 stump 权重（对应 [`feature_vector`]）。
#[derive(Debug, Clone)]
pub struct RouteGateWeights {
    pub bias: f32,
    pub w: [f32; ROUTE_FEATURE_DIM],
    /// 非空时在线性分上叠加 stump（仍 &lt;50µs）。
    pub stumps: Vec<RouteStump>,
}

impl RouteGateWeights {
    /// 与历史硬编码等价的默认权重。
    pub fn builtin() -> Self {
        let mut w = [0.0f32; ROUTE_FEATURE_DIM];
        w[0] = 0.42; // attack_shape
        w[1] = 0.32; // operator_hits_norm
        w[2] = 0.48; // quote_ratio
        w[3] = 0.30; // special_ratio
        w[4] = 0.08; // url_encoded_ratio
        w[5] = 0.015; // entropy_norm
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
        w[20] = 0.10; // pct_hex_dense
        w[21] = 0.04; // key_count_norm
        w[22] = 0.35; // dangerous_key
        w[23] = -0.06; // api_path（干净 API 形降分）
        w[24] = 0.40; // null_byte
        w[25] = 0.12; // base64ish
        w[26] = 0.05; // query_len_norm
        w[27] = -0.08; // structure_clean
        Self {
            bias: 0.0,
            w,
            stumps: Vec::new(),
        }
    }

    /// 从 JSON 加载：`weights` 对象/数组；可选 `stumps`。
    pub fn from_json(text: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct RawStump {
            feature: u16,
            threshold: f32,
            left: f32,
            right: f32,
            alpha: f32,
        }
        #[derive(serde::Deserialize)]
        struct Raw {
            #[serde(default)]
            bias: f32,
            #[serde(default)]
            weights: serde_json::Value,
            #[serde(default)]
            stumps: Vec<RawStump>,
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
        let stumps = raw
            .stumps
            .into_iter()
            .filter(|s| (s.feature as usize) < ROUTE_FEATURE_DIM)
            .map(|s| RouteStump {
                feature: s.feature,
                threshold: s.threshold,
                left: s.left,
                right: s.right,
                alpha: s.alpha,
            })
            .collect();
        Ok(Self {
            bias: raw.bias,
            w,
            stumps,
        })
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
        "pct_hex_dense",
        "key_count_norm",
        "dangerous_key",
        "api_path",
        "null_byte",
        "base64ish",
        "query_len_norm",
        "structure_clean",
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
    /// `%HH` 密度（归一化）。
    pub pct_hex_dense: f32,
    pub key_count: u32,
    pub dangerous_key: bool,
    pub api_path: bool,
    pub null_byte: bool,
    pub base64ish: bool,
    pub query_len: u32,
    pub structure_clean: bool,
}

/// 路由打分结果。
#[derive(Debug, Clone, Copy)]
pub struct RouteDecision {
    pub score: f32,
    pub features: RouteFeatures,
    /// 兼容：硬触发或 score≥deep_threshold。
    pub route_deep: bool,
    /// 硬规则强制 Deep（编码标记 / cache deception / decode·evasion 等），不含分数阈。
    pub hard_deep: bool,
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

/// 优先用 route_preview 浅解码 haystack；为空则回退 raw sample。
/// 同时拼接一段 raw，保留 `%27` 等编码标记供特征/硬规则使用。
pub fn route_sample_for_gate(req: &NativeRequest, views: &RequestViews, max_total: usize) -> String {
    let hay = views.haystack_for_prefilter(max_total.saturating_mul(3) / 4);
    if hay.trim().is_empty() {
        return route_sample(req, max_total);
    }
    let raw = route_sample(req, max_total / 4);
    truncate_utf8_owned(&format!("{hay}\n{raw}"), max_total)
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

/// 统计 `%HH` 百分号编码次数（线性扫描）。
fn count_pct_hex_encodings(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut n = 0u32;
    while i + 2 < b.len() {
        if b[i] == b'%' && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            n = n.saturating_add(1);
            i += 3;
        } else {
            i += 1;
        }
    }
    n
}

fn has_sql_comment_shape(lower: &str) -> bool {
    lower.contains("'--")
        || lower.contains(";--")
        || lower.contains(" #")
        || lower.contains("%23")
        || (lower.contains("--") && (lower.contains('\'') || lower.contains(';')))
}

/// 计算特征（ASCII 归一化样本；样本应来自浅解码预览优先）。
pub fn extract_features(req: &NativeRequest, sample: &str) -> RouteFeatures {
    let lower = sample.to_ascii_lowercase();
    let len = lower.len().max(1) as u32;

    let mut quotes = 0u32;
    let mut special = 0u32;
    let mut byte_freq = [0u32; 256];
    for &b in lower.as_bytes() {
        byte_freq[b as usize] = byte_freq[b as usize].saturating_add(1);
        match b {
            b'\'' | b'"' => quotes += 1,
            b'<' | b'>' | b';' | b'(' | b')' | b'|' | b'`' | b'\\' => special += 1,
            _ => {}
        }
    }
    let url_enc = count_pct_hex_encodings(&lower);

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
    let keys = crate::structure_anchor::extract_param_keys(req);
    let dangerous_key = keys.iter().any(|k| {
        let l = k.to_ascii_lowercase();
        l.contains("__proto__")
            || l.starts_with('$')
            || matches!(l.as_str(), "constructor" | "prototype" | "$where")
    });
    let path = req.uri.split('?').next().unwrap_or(req.uri.as_str());
    let api_path = path.starts_with("/api/") || path.starts_with("/open/api/");
    let structure_clean = matches!(
        crate::structure_anchor::classify_structure(req),
        crate::structure_anchor::StructureClass::Clean
    );
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
        sql_comment: has_sql_comment_shape(&lower),
        xss_angle: lower.contains('<') || lower.contains("%3c"),
        path_traversal: lower.contains("../") || lower.contains("%2e%2e"),
        pct_hex_dense: (url_enc as f32 / 16.0).min(1.0),
        key_count: keys.len().min(64) as u32,
        dangerous_key,
        api_path,
        null_byte: lower.contains("%00") || lower.contains('\0'),
        base64ish: looks_base64ish(&lower),
        query_len: req.query.len().min(4096) as u32,
        structure_clean,
    }
}

fn looks_base64ish(lower: &str) -> bool {
    // 连续 ≥40 的 base64 字母数字/+/= 视为 blob 形
    let mut run = 0u32;
    for &b in lower.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            run = run.saturating_add(1);
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// 28 维特征向量（归一化到约 0–1）。
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
        f.pct_hex_dense,
        (f.key_count as f32 / 32.0).min(1.0),
        f32::from(f.dangerous_key),
        f32::from(f.api_path),
        f32::from(f.null_byte),
        f32::from(f.base64ish),
        (f.query_len as f32 / 512.0).min(1.0),
        f32::from(f.structure_clean),
    ]
}

pub fn score_features(f: &RouteFeatures, weights: &RouteGateWeights) -> f32 {
    let fv = feature_vector(f);
    let mut s = weights.bias;
    for (i, v) in fv.iter().enumerate() {
        s += weights.w[i] * v;
    }
    for stump in &weights.stumps {
        let idx = stump.feature as usize;
        if idx >= ROUTE_FEATURE_DIM {
            continue;
        }
        let x = fv[idx];
        let leaf = if x < stump.threshold {
            stump.left
        } else {
            stump.right
        };
        s += stump.alpha * leaf;
    }
    s.clamp(0.0, 1.0)
}

/// 是否应走深路径（结合硬 hint 与门闩分）。
pub fn decide_deep(
    cfg: &RouteGateConfig,
    req: &NativeRequest,
    views: &RequestViews,
    decode_hint: bool,
    evasion_hint: bool,
    cache_deception: bool,
    has_response: bool,
) -> RouteDecision {
    let sample = route_sample_for_gate(req, views, 12 * 1024);
    let features = extract_features(req, &sample);
    let score = score_features(&features, &cfg.weights);

    if !cfg.enabled {
        return RouteDecision {
            score,
            features,
            route_deep: true,
            hard_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }

    if cache_deception || has_response {
        return RouteDecision {
            score: 1.0,
            features,
            route_deep: true,
            hard_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }
    if cfg.hard_decode_hint && (decode_hint || evasion_hint) {
        return RouteDecision {
            score: 1.0,
            features,
            route_deep: true,
            hard_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }
    // 百分号编码攻击标记：Fast 路径默认无解码，必须升 deep
    if raw_has_encoded_attack_markers(req) {
        return RouteDecision {
            score: 1.0,
            features,
            route_deep: true,
            hard_deep: true,
            clean_json_api: false,
            api_positive_lane: false,
        };
    }

    let api_lane = is_api_positive_lane(req, &features, decode_hint, evasion_hint);
    if is_clean_json_api(&features, decode_hint, evasion_hint) || api_lane {
        return RouteDecision {
            score,
            features,
            route_deep: false,
            hard_deep: false,
            clean_json_api: !api_lane,
            api_positive_lane: api_lane,
        };
    }
    let over_deep = score >= cfg.deep_threshold;
    RouteDecision {
        score,
        features,
        route_deep: over_deep,
        hard_deep: false,
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
        // URL 编码常见形态（route 样本可能尚未完全解码）
        || hay.contains("%27")
        || hay.contains("%3c")
        || hay.contains("union%20select")
        || hay.contains("%2e%2e")
}

fn raw_has_encoded_attack_markers(req: &NativeRequest) -> bool {
    let hay = format!("{} {} {}", req.uri, req.query, req.body).to_ascii_lowercase();
    hay.contains("%27")
        || hay.contains("%22")
        || hay.contains("%3c")
        || hay.contains("%3e")
        || hay.contains("%3b")
        || hay.contains("%2e%2e")
        || hay.contains("%252e")
        || hay.contains("%2500")
        || hay.contains("%00")
        || hay.contains("%0d%0a")
        || hay.contains("%2f%2e%2e")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_sqli_routes_deep() {
        let req = NativeRequest {
            method: "GET".into(),
            uri: "/x".into(),
            query: "id=1%27%20or%20%271%27%3D%271".into(),
            ..Default::default()
        };
        let cfg = RouteGateConfig::default();
        let views = RequestViews::default();
        let d = decide_deep(&cfg, &req, &views, false, false, false, false);
        assert!(d.route_deep, "encoded sqli must deep: score={}", d.score);
    }

    #[test]
    fn pct_hex_count_linear() {
        let n = count_pct_hex_encodings("a%27b%3cc%ZZ%2");
        assert_eq!(n, 2);
    }

    #[test]
    fn sql_comment_ignores_bare_hash() {
        assert!(!has_sql_comment_shape("tag#channel"));
        assert!(has_sql_comment_shape("1'--"));
        assert!(has_sql_comment_shape("x;--y"));
    }

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
