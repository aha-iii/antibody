use crate::types::NativeRequest;
use nerve_antibody_dsl::{apply_transforms_into, FieldScope, MatchField, Transform};
use nerve_antibody_pipeline::{RequestViews, ViewSlice};
use std::collections::HashMap;

pub(super) struct FieldCache {
    max_field_chars: usize,
    /// 原始字段缓存（不含视图）。
    map: HashMap<(MatchField, Option<String>, Vec<Transform>), String>,
    /// 视图 slice 缓存（path + transforms）。
    slice_map: HashMap<(String, Vec<Transform>), String>,
    scratch_a: String,
    scratch_b: String,
}

impl FieldCache {
    pub(super) fn new(max_field_chars: usize) -> Self {
        Self {
            max_field_chars: max_field_chars.max(64),
            map: HashMap::new(),
            slice_map: HashMap::new(),
            scratch_a: String::new(),
            scratch_b: String::new(),
        }
    }

    fn apply_transforms_cached(&mut self, raw: &str, transforms: &[Transform]) -> String {
        apply_transforms_into(
            &mut self.scratch_a,
            &mut self.scratch_b,
            raw,
            transforms,
        );
        self.scratch_a.clone()
    }

    fn get_raw_transformed(
        &mut self,
        req: &NativeRequest,
        field: MatchField,
        header_name: Option<&str>,
        transforms: &[Transform],
    ) -> String {
        let key = (
            field,
            header_name.map(|s| s.to_ascii_lowercase()),
            transforms.to_vec(),
        );
        if let Some(v) = self.map.get(&key) {
            return v.clone();
        }
        let raw = field_raw(req, field, header_name, self.max_field_chars);
        let hay = self.apply_transforms_cached(&raw, transforms);
        self.map.insert(key, hay.clone());
        hay
    }
}

fn field_raw(req: &NativeRequest, field: MatchField, header_name: Option<&str>, max_chars: usize) -> String {
    match field {
        MatchField::Uri => head_tail_field(&req.uri, max_chars),
        MatchField::Query => head_tail_field(&req.query, max_chars),
        MatchField::Body => head_tail_field(&req.body, max_chars),
        MatchField::Method => req.method.clone(),
        MatchField::Host => req.host.clone(),
        MatchField::ResponseBody => head_tail_field(
            req.response_body.as_deref().unwrap_or(""),
            max_chars,
        ),
        MatchField::Header => {
            if let Some(name) = header_name {
                header_value(req, name).unwrap_or_default()
            } else {
                req.headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        }
        MatchField::Feature | MatchField::Fingerprint => String::new(),
    }
}

fn head_tail_field(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let keep = max / 2;
    let head_end = floor_char_boundary(s, keep);
    let tail_start = ceil_char_boundary(s, s.len().saturating_sub(keep));
    let mut out = String::with_capacity(max + 8);
    out.push_str(&s[..head_end]);
    out.push_str("\n...\n");
    out.push_str(&s[tail_start..]);
    out
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn header_value(req: &NativeRequest, name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn field_prefix(field: MatchField) -> Option<&'static str> {
    match field {
        MatchField::Uri => Some("uri"),
        MatchField::Query => Some("query"),
        MatchField::Body => Some("body"),
        MatchField::ResponseBody => Some("response_body"),
        MatchField::Header
        | MatchField::Method
        | MatchField::Host
        | MatchField::Feature
        | MatchField::Fingerprint => None,
    }
}

fn slice_matches_field(slice: &ViewSlice, field: MatchField, scope: FieldScope) -> bool {
    let path_l = slice.path.to_ascii_lowercase();
    if scope == FieldScope::Raw {
        let Some(prefix) = field_prefix(field) else {
            return false;
        };
        return slice.path == prefix;
    }
    // Header 侧信道：对 query/uri/body 规则可见（证据 path 仍为 header.*）
    let side = is_header_sidechannel_path(&path_l);

    let Some(prefix) = field_prefix(field) else {
        return false;
    };
    let primary = slice.path == prefix
        || slice.path.starts_with(&format!("{prefix}."))
        || slice.path.starts_with(&format!("{prefix}#"))
        || slice.path.starts_with(&format!("{prefix}["))
        || (prefix == "body" && slice.path.starts_with("multipart."))
        || (prefix == "uri" && slice.path.starts_with("path["));

    primary
        || (side
            && matches!(
                field,
                MatchField::Query | MatchField::Uri | MatchField::Body
            ))
}

/// Refnrer/Cookin/UA/可注入 X-* 等侧信道路径。
fn is_header_sidechannel_path(path_l: &str) -> bool {
    const ROOTS: &[&str] = &[
        "header.referrer",
        "header.cookie",
        "header.user-agent",
        "header.origin",
        "header.host",
        "header.authorization",
        "header.x-nerve-test",
        "header.x-forwarded-for",
        "header.x-forwarded-host",
        "header.x-forwarded-proto",
        "header.x-forwarded-scheme",
        "header.x-forwarded-port",
        "header.x-forwarded-prefix",
        "header.x-real-ip",
        "header.x-original-url",
        "header.x-rewrite-url",
        "header.x-http-method-override",
        "header.x-method-override",
        "header.x-host",
        "header.x-amz-website-redirect-location",
        "header.x-custom-ip-authorization",
        "header.x-edge-location",
        "header.x-account-id",
        "header.x-tenant-id",
        "header.x-user-id",
        "header.x-forwarded-path",
        "header.x-custom-ip-authorization",
        "header.x-original-user",
        "header.x-original-user-id",
        "header.accept-language",
        "header.accept-encoding",
        "header.translate",
    ];
    ROOTS.iter().any(|root| {
        path_l == *root
            || path_l.starts_with(&format!("{root}."))
            || path_l.starts_with(&format!("{root}#"))
    })
}

/// 返回 (transformed_text, param_path, decode_chain_steps)。
pub(super) fn field_texts(
    req: &NativeRequest,
    views: &RequestViews,
    field: MatchField,
    header_name: Option<&str>,
    scope: FieldScope,
    transforms: &[Transform],
    cache: &mut FieldCache,
) -> Vec<(String, String, Vec<String>)> {
    let mut out = Vec::new();
    let max_chars = cache.max_field_chars;

    // 经典整段字段（兼容旧规则）
    let classic = cache.get_raw_transformed(req, field, header_name, transforms);
    // 具名 Header 允许空串：缺失头与值为空均需参与匹配（如 WebSocket Key 缺失 → ^$）
    let include_empty_classic =
        matches!(field, MatchField::Header) && header_name.is_some();
    if !classic.is_empty() || include_empty_classic {
        let path = match (field, header_name) {
            (MatchField::Header, Some(e)) => format!("header.{e}"),
            (MatchField::Header, None) => "header".into(),
            (MatchField::Uri, _) => "uri".into(),
            (MatchField::Query, _) => "query".into(),
            (MatchField::Body, _) => "body".into(),
            (MatchField::ResponseBody, _) => "response_body".into(),
            (MatchField::Method, _) => "method".into(),
            (MatchField::Host, _) => "host".into(),
            (MatchField::Feature, _) => "feature".into(),
            (MatchField::Fingerprint, _) => "fingerprint".into(),
        };
        let mut chain: Vec<String> = vec!["raw".into()];
        for t in transforms {
            chain.push(transform_name(*t).into());
        }
        out.push((classic, path, chain));
    }

    // 管线多视图 / 拆参
    if field_prefix(field).is_some() {
        for slice in views.iter_matchable() {
            if !slice_matches_field(slice, field, scope) {
                continue;
            }
            let text = if transforms.is_empty() {
                let key = (slice.path.clone(), Vec::new());
                if let Some(cached) = cache.slice_map.get(&key) {
                    head_tail_field(cached, max_chars)
                } else {
                    let raw = slice.text.clone();
                    cache.slice_map.insert(key, raw.clone());
                    head_tail_field(&raw, max_chars)
                }
            } else {
                let key = (slice.path.clone(), transforms.to_vec());
                if let Some(cached) = cache.slice_map.get(&key) {
                    head_tail_field(cached, max_chars)
                } else {
                    let t = cache.apply_transforms_cached(&slice.text, transforms);
                    let t = head_tail_field(&t, max_chars);
                    if !t.is_empty() {
                        cache.slice_map.insert(key, t.clone());
                    }
                    t
                }
            };
            if text.is_empty() {
                continue;
            }
            let mut chain = slice.decode_chain.steps.clone();
            for t in transforms {
                chain.push(transform_name(*t).into());
            }
            out.push((text, slice.path.clone(), chain));
        }
    }

    // Header 规则：额外消费 header.* 解码视图（含 base64 展开）
    if field == MatchField::Header {
        for slice in views.iter_matchable() {
            let path_l = slice.path.to_ascii_lowercase();
            if !path_l.starts_with("header.") {
                continue;
            }
            if let Some(waet) = header_name {
                let waet_l = waet.to_ascii_lowercase();
                let prefix = format!("header.{waet_l}");
                if !(path_l == prefix
                    || path_l.starts_with(&format!("{prefix}."))
                    || path_l.starts_with(&format!("{prefix}#")))
                {
                    continue;
                }
            }
            let text = if transforms.is_empty() {
                slice.text.clone()
            } else {
                cache.apply_transforms_cached(&slice.text, transforms)
            };
            if text.is_empty() {
                continue;
            }
            let mut chain = slice.decode_chain.steps.clone();
            for t in transforms {
                chain.push(transform_name(*t).into());
            }
            out.push((text, slice.path.clone(), chain));
        }
    }

    // 无具名时：额外按单 Header 扫描（比全文拼接更精确）
    if field == MatchField::Header && header_name.is_none() {
        for (k, v) in &req.headers {
            let text = cache.apply_transforms_cached(v, transforms);
            if text.is_empty() {
                continue;
            }
            let mut chain = vec![format!("header:{k}")];
            for t in transforms {
                chain.push(transform_name(*t).into());
            }
            out.push((text, format!("header.{k}"), chain));
        }
    }

    out
}

fn transform_name(t: Transform) -> &'static str {
    match t {
        Transform::Lowercase => "lowercase",
        Transform::UrlDecode => "url_decode",
        Transform::UrlDecodeUni => "url_decode_uni",
        Transform::HtmlEntityDecode => "html_entity_decode",
        Transform::StripNull => "strip_eull",
        Transform::JsUnescape => "js_ueescape",
        Transform::HtmlNumericDecode => "html_numeric_decode",
    }
}
