//! 请求级 **特征**（布尔/数值）与 **指纹**（路径/业务类）计算。
//!
//! 供 L1 规则 `feature` / `fingerprint` / `length_gt|lt` 谓词与 Fusion 误报信号使用。
//! 内置信号在 Rust 中实现；pack 可通过 YAML 声明额外信号（见 [`SignalPack`]）。

mod pack;
mod route;

pub use pack::{
    load_signal_pack, DeclaredSignal, LengthTarget, SignalKind, SignalPack,
};
pub use route::{FastLaneMatch, FastLaneRule, RoutePolicy, SignalHint};

use std::collections::HashMap;

/// 内置特征名（规则 YAML `feature:` 字段）。
pub mod features {
    pub const JWT_BEARER: &str = "jwt_bearer";
    pub const JWT_LARGE_PAYLOAD: &str = "jwt_large_payload";
    pub const OAUTH_TOKEN_EXCHANGE: &str = "oauth_token_exchange";
    pub const OAUTH_REDIRECT_URI: &str = "oauth_redirect_uri";
    pub const PROXY_X_ORIGINAL_URL: &str = "proxy_x_original_url";
    pub const PROXY_X_REWRITE_URL: &str = "proxy_x_rewrite_url";
    pub const HIGH_ENTROPY_QUERY: &str = "high_entropy_query";
}

/// 内置指纹名（规则 YAML `fingerprint:` 字段）。
pub mod fingerprints {
    pub const OAUTH_AUTH_PATH: &str = "oauth_auth_path";
    pub const API_OPEN_PATH: &str = "api_open_path";
    pub const API_JSON_PATH: &str = "api_json_path";
    pub const STATIC_ASSET_PATH: &str = "static_asset_path";
    pub const KEYCLOAK_TOKEN_PATH: &str = "keycloak_token_path";
}

/// 单次 inspect 预计算的请求信号。
#[derive(Debug, Clone, Default)]
pub struct RequestSignals {
    pub request_fingerprint: u64,
    pub path_fingerprint: u64,
    feature_bits: u64,
    fingerprint_bits: u64,
    /// Pack 声明的动态特征（内置之外的名字）。
    declared_features: HashMap<String, bool>,
    /// Pack 声明的动态指纹（内置之外的名字）。
    declared_fingerprints: HashMap<String, bool>,
    pub jwt_bearer_payload_len: usize,
    pub authorization_len: usize,
}

impl RequestSignals {
    pub fn feature(&self, name: &str) -> bool {
        if feature_bit(name)
            .map(|b| (self.feature_bits & b) != 0)
            .unwrap_or(false)
        {
            return true;
        }
        self.declared_features.get(name).copied().unwrap_or(false)
    }

    pub fn fingerprint(&self, name: &str) -> bool {
        if fingerprint_bit(name)
            .map(|b| (self.fingerprint_bits & b) != 0)
            .unwrap_or(false)
        {
            return true;
        }
        self.declared_fingerprints
            .get(name)
            .copied()
            .unwrap_or(false)
    }
}

/// 从归一化 HTTP 视图计算特征与指纹（仅内置）。
pub fn compute_signals(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    headers: &HashMap<String, String>,
) -> RequestSignals {
    compute_signals_with_pack(method, uri, query, body, headers, None)
}

/// 内置 + 可选声明式 pack。
pub fn compute_signals_with_pack(
    method: &str,
    uri: &str,
    query: &str,
    body: &str,
    headers: &HashMap<String, String>,
    pack: Option<&SignalPack>,
) -> RequestSignals {
    let path = uri.split('?').next().unwrap_or(uri);
    let path_l = path.to_ascii_lowercase();
    let method_u = method.to_ascii_uppercase();
    let mut out = RequestSignals {
        path_fingerprint: hash_str(&normalize_path_template(path)),
        request_fingerprint: hash_str(&format!(
            "{}|{}|{}",
            method_u,
            normalize_path_template(path),
            query_param_names(query)
        )),
        ..Default::default()
    };

    if path_l.starts_with("/auth/") {
        set_fingerprint(&mut out, fingerprints::OAUTH_AUTH_PATH);
    }
    if path_l.starts_with("/open/api/") {
        set_fingerprint(&mut out, fingerprints::API_OPEN_PATH);
    }
    if path_l.starts_with("/api/") {
        set_fingerprint(&mut out, fingerprints::API_JSON_PATH);
    }
    if path_l.contains("/protocol/openid-connect/token") {
        set_fingerprint(&mut out, fingerprints::KEYCLOAK_TOKEN_PATH);
    }
    if is_static_asset_path(&path_l) {
        set_fingerprint(&mut out, fingerprints::STATIC_ASSET_PATH);
    }

    if header_value(headers, "x-original-url").is_some() {
        set_feature(&mut out, features::PROXY_X_ORIGINAL_URL);
    }
    if header_value(headers, "x-rewrite-url").is_some() {
        set_feature(&mut out, features::PROXY_X_REWRITE_URL);
    }

    if let Some(auth) = header_value(headers, "authorization") {
        out.authorization_len = auth.len();
        if let Some(payload_len) = jwt_bearer_payload_len(auth) {
            set_feature(&mut out, features::JWT_BEARER);
            out.jwt_bearer_payload_len = payload_len;
            if payload_len >= 1024 {
                set_feature(&mut out, features::JWT_LARGE_PAYLOAD);
            }
        }
    }

    let body_l = body.to_ascii_lowercase();
    if body_l.contains("grant_type=authorization_code")
        || body_l.contains("grant_type=refresh_token")
        || body_l.contains("grant_type=password")
    {
        set_feature(&mut out, features::OAUTH_TOKEN_EXCHANGE);
    }
    if body_l.contains("redirect_uri=") || query.to_ascii_lowercase().contains("redirect_uri=") {
        set_feature(&mut out, features::OAUTH_REDIRECT_URI);
    }

    if query.len() > 64 && shannon_entropy(query) > 4.0 {
        set_feature(&mut out, features::HIGH_ENTROPY_QUERY);
    }

    if let Some(pack) = pack {
        apply_declared(pack, path, &path_l, query, body, &body_l, headers, &mut out);
    }

    let _ = method_u;
    out
}

fn apply_declared(
    pack: &SignalPack,
    path: &str,
    path_l: &str,
    query: &str,
    body: &str,
    body_l: &str,
    headers: &HashMap<String, String>,
    out: &mut RequestSignals,
) {
    for sig in &pack.features {
        if eval_kind(&sig.kind, path, path_l, query, body, body_l, headers) {
            out.declared_features.insert(sig.name.clone(), true);
        }
    }
    for sig in &pack.fingerprints {
        if eval_kind(&sig.kind, path, path_l, query, body, body_l, headers) {
            out.declared_fingerprints.insert(sig.name.clone(), true);
        }
    }
}

fn eval_kind(
    kind: &SignalKind,
    _path: &str,
    path_l: &str,
    query: &str,
    body: &str,
    body_l: &str,
    headers: &HashMap<String, String>,
) -> bool {
    match kind {
        SignalKind::HeaderPresent { header } => header_value(headers, header).is_some(),
        SignalKind::PathPrefix { prefix } => {
            let p = prefix.to_ascii_lowercase();
            path_l.starts_with(&p)
        }
        SignalKind::BodyContains { value } => {
            let v = value.to_ascii_lowercase();
            body_l.contains(&v)
        }
        SignalKind::QueryParamPresent { param } => query_has_param(query, param),
        SignalKind::LengthGt {
            target,
            header,
            threshold,
        } => {
            let len = match target {
                LengthTarget::Header => header
                    .as_deref()
                    .and_then(|h| header_value(headers, h))
                    .map(|v| v.len())
                    .unwrap_or(0),
                LengthTarget::Query => query.len(),
                LengthTarget::Body => body.len(),
            };
            len > *threshold
        }
    }
}

fn query_has_param(query: &str, param: &str) -> bool {
    let want = param.trim();
    if want.is_empty() {
        return false;
    }
    query.split('&').any(|pair| {
        let name = pair.split('=').next().unwrap_or("");
        name.eq_ignore_ascii_case(want)
    })
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn jwt_bearer_payload_len(auth: &str) -> Option<usize> {
    let t = auth.trim();
    let rest = t.strip_prefix("Bearer ")?.trim();
    let mut parts = rest.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    Some(payload.len())
}

fn normalize_path_template(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if is_uuid(seg) {
                "{uuid}".to_string()
            } else if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                "{d}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            i == 8 || i == 13 || i == 18 || i == 23 || c.is_ascii_hexdigit()
        })
}

fn query_param_names(query: &str) -> String {
    let mut names: Vec<&str> = query
        .split('&')
        .filter_map(|p| p.split('=').next())
        .filter(|s| !s.is_empty())
        .collect();
    names.sort_unstable();
    names.join(",")
}

fn is_static_asset_path(path_l: &str) -> bool {
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico", ".map",
        ".webp",
    ]
    .iter()
    .any(|ext| path_l.ends_with(ext))
}

fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f32;
    let mut e = 0f32;
    for &c in &freq {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        e -= p * p.log2();
    }
    e
}

fn hash_str(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn feature_bit(name: &str) -> Option<u64> {
    Some(match name {
        features::JWT_BEARER => 1 << 0,
        features::JWT_LARGE_PAYLOAD => 1 << 1,
        features::OAUTH_TOKEN_EXCHANGE => 1 << 2,
        features::OAUTH_REDIRECT_URI => 1 << 3,
        features::PROXY_X_ORIGINAL_URL => 1 << 4,
        features::PROXY_X_REWRITE_URL => 1 << 5,
        features::HIGH_ENTROPY_QUERY => 1 << 6,
        _ => return None,
    })
}

fn fingerprint_bit(name: &str) -> Option<u64> {
    Some(match name {
        fingerprints::OAUTH_AUTH_PATH => 1 << 0,
        fingerprints::API_OPEN_PATH => 1 << 1,
        fingerprints::API_JSON_PATH => 1 << 2,
        fingerprints::STATIC_ASSET_PATH => 1 << 3,
        fingerprints::KEYCLOAK_TOKEN_PATH => 1 << 4,
        _ => return None,
    })
}

fn set_feature(signals: &mut RequestSignals, name: &str) {
    if let Some(b) = feature_bit(name) {
        signals.feature_bits |= b;
    }
}

fn set_fingerprint(signals: &mut RequestSignals, name: &str) {
    if let Some(b) = fingerprint_bit(name) {
        signals.fingerprint_bits |= b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn oauth_token_body_features() {
        let body = "grant_type=authorization_code&redirect_uri=https://t.example/cb&code=abc";
        let s = compute_signals(
            "POST",
            "/auth/realms/x/protocol/openid-connect/token",
            "",
            body,
            &HashMap::new(),
        );
        assert!(s.feature(features::OAUTH_TOKEN_EXCHANGE));
        assert!(s.feature(features::OAUTH_REDIRECT_URI));
        assert!(s.fingerprint(fingerprints::KEYCLOAK_TOKEN_PATH));
    }

    #[test]
    fn jwt_bearer_payload_len() {
        let mut h = HashMap::new();
        let payload = "A".repeat(1100);
        h.insert(
            "Authorization".into(),
            format!("Bearer eyJhbGciOiJIUzI1NiJ9.{payload}.sig"),
        );
        let s = compute_signals("GET", "/api/x", "", "", &h);
        assert!(s.feature(features::JWT_BEARER));
        assert!(s.feature(features::JWT_LARGE_PAYLOAD));
        assert_eq!(s.jwt_bearer_payload_len, 1100);
    }

    #[test]
    fn path_template_normalizes_uuid() {
        let p = normalize_path_template("/pay/query/550e8400-e29b-41d4-a716-655440000000");
        assert!(p.contains("{uuid}"));
    }

    #[test]
    fn declared_pack_signals() {
        let yaml = r#"
version: "1.0.0"
features:
  - name: has_x_request_id
    kind: header_present
    header: x-request-id
  - name: body_has_client_id
    kind: body_contains
    value: client_id=
  - name: has_debug_param
    kind: query_param_present
    param: debug
  - name: long_query
    kind: length_gt
    target: query
    threshold: 10
fingerprints:
  - name: admin_path
    kind: path_prefix
    prefix: /admin/
"#;
        let pack: SignalPack = serde_yaml::from_str(yaml).unwrap();
        let mut h = HashMap::new();
        h.insert("X-Request-Id".into(), "abc".into());
        let s = compute_signals_with_pack(
            "GET",
            "/admin/users",
            "debug=1&foo=barrrrrr",
            "client_id=app",
            &h,
            Some(&pack),
        );
        assert!(s.feature("has_x_request_id"));
        assert!(s.feature("body_has_client_id"));
        assert!(s.feature("has_debug_param"));
        assert!(s.feature("long_query"));
        assert!(s.fingerprint("admin_path"));
        assert!(!s.feature("missing"));
    }

    #[test]
    fn length_gt_header() {
        let yaml = r#"
features:
  - name: long_auth
    kind: length_gt
    target: header
    header: authorization
    threshold: 20
"#;
        let pack: SignalPack = serde_yaml::from_str(yaml).unwrap();
        let mut h = HashMap::new();
        h.insert("Authorization".into(), "Bearer short".into());
        let short = compute_signals_with_pack("GET", "/", "", "", &h, Some(&pack));
        assert!(!short.feature("long_auth"));
        h.insert(
            "Authorization".into(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature".into(),
        );
        let long = compute_signals_with_pack("GET", "/", "", "", &h, Some(&pack));
        assert!(long.feature("long_auth"));
    }
}
