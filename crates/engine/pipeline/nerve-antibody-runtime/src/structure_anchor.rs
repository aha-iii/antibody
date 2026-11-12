//! Nerve RIS L2：结构锚定（方法 + 路径模板 + CT 类 + 参数键集合）。
//!
//! 只影响分流分区，不参与 block 定罪。

use crate::types::NativeRequest;
use std::collections::BTreeSet;

/// 结构分类结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureClass {
    /// 像已知干净 API 形 → 倾向 clean Fast
    Clean,
    /// 无强信号
    Neutral,
    /// 键集合 / 形态异常 → 至少 gray
    Anomaly,
}

/// URI 路径模板：数字段→`{d}`，UUID→`{uuid}`。
pub fn path_template(uri: &str) -> String {
    uri.split('?')
        .next()
        .unwrap_or(uri)
        .split('/')
        .map(|seg| {
            if seg.is_empty() {
                return String::new();
            }
            if seg.bytes().all(|b| b.is_ascii_digit()) {
                "{d}".into()
            } else if seg.len() == 36 && seg.as_bytes().iter().filter(|&&b| b == b'-').count() == 4
            {
                "{uuid}".into()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn ct_class(req: &NativeRequest) -> &'static str {
    let ct = req.content_type().unwrap_or("").to_ascii_lowercase();
    if ct.contains("json") {
        "json"
    } else if ct.contains("multipart") {
        "multipart"
    } else if ct.contains("www-form-urlencoded") || ct.contains("form-urlencoded") {
        "form"
    } else if ct.is_empty() {
        "none"
    } else {
        "other"
    }
}

/// 从 query 与（浅）JSON body 顶层提取参数键名。
pub fn extract_param_keys(req: &NativeRequest) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for part in req.query.split('&') {
        if part.is_empty() {
            continue;
        }
        let k = part.split('=').next().unwrap_or(part).trim();
        if !k.is_empty() {
            keys.insert(k.to_string());
        }
    }
    if ct_class(req) == "json" && !req.body.is_empty() && req.body.len() <= 65_536 {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req.body) {
            if let Some(obj) = v.as_object() {
                for k in obj.keys() {
                    keys.insert(k.clone());
                }
            }
        }
    }
    keys
}

fn key_looks_safe(k: &str) -> bool {
    if k.is_empty() || k.len() > 64 {
        return false;
    }
    let b = k.as_bytes();
    if !b[0].is_ascii_alphabetic() && b[0] != b'_' {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(*c, b'_' | b'-' | b'.'))
}

fn key_is_dangerous(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    matches!(
        l.as_str(),
        "__proto__"
            | "constructor"
            | "prototype"
            | "$where"
            | "$gt"
            | "$ne"
            | "passwd"
            | "password"
    ) || l.contains("__proto__")
        || l.starts_with('$')
}

/// 结构指纹（方法+路径模板+CT+键集合），供 L1/L5 记忆。
pub fn structure_fingerprint(req: &NativeRequest) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    req.method.to_ascii_uppercase().hash(&mut h);
    path_template(&req.uri).hash(&mut h);
    ct_class(req).hash(&mut h);
    for k in extract_param_keys(req) {
        k.hash(&mut h);
    }
    h.finish()
}

fn api_shaped_path(path: &str) -> bool {
    path.starts_with("/api/")
        || path.starts_with("/open/api/")
        || path == "/api"
        || path == "/health"
        || path == "/ready"
        || path.starts_with("/health/")
        || path == "/favicon.ico"
}

/// 分类请求结构（不含内容攻击打分；调用方需结合 hard_deep）。
pub fn classify_structure(req: &NativeRequest) -> StructureClass {
    let path = path_template(&req.uri);
    let keys = extract_param_keys(req);
    if keys.iter().any(|k| key_is_dangerous(k)) {
        return StructureClass::Anomaly;
    }
    if keys.len() > 48 {
        return StructureClass::Anomaly;
    }
    if keys.iter().any(|k| !key_looks_safe(k)) {
        return StructureClass::Anomaly;
    }
    // 超大非 JSON body 且无 query：中性（交给 L3）
    if !req.body.is_empty() && ct_class(req) != "json" && keys.is_empty() && req.body.len() > 4096 {
        return StructureClass::Neutral;
    }
    let method = req.method.to_ascii_uppercase();
    let benign_get = method == "GET"
        && req.body.is_empty()
        && keys.len() <= 16
        && (api_shaped_path(&path) || keys.is_empty());
    let benign_json = matches!(method.as_str(), "POST" | "PUT" | "PATCH")
        && ct_class(req) == "json"
        && api_shaped_path(&path)
        && keys.len() <= 32
        && req.body.len() <= 65_536;
    if benign_get || benign_json {
        return StructureClass::Clean;
    }
    StructureClass::Neutral
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NativeRequest;

    #[test]
    fn api_get_keys_are_clean() {
        let req = NativeRequest {
            method: "GET".into(),
            uri: "/api/search".into(),
            query: "q=hello-world&page=1&id=550e8400-e29b-41d4-a716-446655440000".into(),
            ..Default::default()
        };
        assert_eq!(classify_structure(&req), StructureClass::Clean);
        let keys = extract_param_keys(&req);
        assert!(keys.contains("q") && keys.contains("page") && keys.contains("id"));
    }

    #[test]
    fn proto_key_is_anomaly() {
        let req = NativeRequest {
            method: "POST".into(),
            uri: "/api/x".into(),
            body: r#"{"__proto__":{"x":1}}"#.into(),
            content_type: Some("application/json".into()),
            ..Default::default()
        };
        assert_eq!(classify_structure(&req), StructureClass::Anomaly);
    }

    #[test]
    fn path_template_digits() {
        assert_eq!(
            path_template("/api/users/123/items"),
            "/api/users/{d}/items"
        );
    }
}
