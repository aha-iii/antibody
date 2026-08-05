//! 结构化拆参：form / JSON / multipart / XML(SOAP)。

mod xml;

use crate::views::ParamUnit;

/// 拆参选项。
#[derive(Debug, Clone)]
pub struct StructuralOptions {
    pub max_params: usize,
}

impl Default for StructuralOptions {
    fn default() -> Self {
        Self { max_params: 256 }
    }
}

/// 结构化解析器。
pub struct StructuralParser;

impl StructuralParser {
    pub fn extract(
        _method: &str,
        uri: &str,
        query: &str,
        body: &str,
        content_type: Option<&str>,
        opts: &StructuralOptions,
    ) -> Vec<ParamUnit> {
        let mut out = Vec::new();
        push_query(&mut out, query, opts.max_params);
        // path segments as weak params
        for (i, seg) in uri.split('/').filter(|s| !s.is_empty()).enumerate() {
            if out.len() >= opts.max_params {
                break;
            }
            if seg.len() > 1 {
                out.push(ParamUnit {
                    path: format!("path[{i}]"),
                    value: seg.to_string(),
                    source: "path".into(),
                });
            }
        }

        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        if ct.contains("application/json") || body.trim_start().starts_with('{') || body.trim_start().starts_with('[')
        {
            push_json(&mut out, body, opts.max_params);
        } else if ct.contains("multipart/") {
            push_multipart(&mut out, body, opts.max_params);
        } else if xml::looks_like_xml(&ct, body) {
            xml::push_xml(&mut out, body, opts.max_params);
        } else if ct.contains("application/x-www-form-urlencoded")
            || (!body.is_empty() && body.contains('=') && !body.trim_start().starts_with('<'))
        {
            push_form(&mut out, body, "body", opts.max_params);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_extract_wires_soap_xml() {
        let body = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Echo><msg><![CDATA[<script>alert(1)</script>]]></msg></Echo>
  </soap:Body>
</soap:Envelope>"#;
        let params = StructuralParser::extract(
            "POST",
            "/soap",
            "",
            body,
            Some("text/xml"),
            &StructuralOptions::default(),
        );
        assert!(
            params.iter().any(|p| {
                p.source == "xml"
                    && p.path == "body.xml.tag:msg"
                    && p.value.to_ascii_lowercase().contains("<script")
            }),
            "SOAP structural path missing: {params:?}"
        );
    }
}

fn push_query(out: &mut Vec<ParamUnit>, query: &str, max: usize) {
    push_form(out, query, "query", max);
}

fn push_form(out: &mut Vec<ParamUnit>, s: &str, source: &str, max: usize) {
    for pair in s.split('&') {
        if out.len() >= max {
            break;
        }
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = urlencoding_loose(k);
        let val = urlencoding_loose(v);
        out.push(ParamUnit {
            path: format!("{source}.{key}"),
            value: val,
            source: source.into(),
        });
    }
}

fn urlencoding_loose(s: &str) -> String {
    // 轻量：交给后续 DecodePipeline；此处仅 + → space
    s.replace('+', " ")
}

fn push_json(out: &mut Vec<ParamUnit>, body: &str, max: usize) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return;
    };
    walk_json(out, &v, "body", max);
}

fn walk_json(out: &mut Vec<ParamUnit>, v: &serde_json::Value, path: &str, max: usize) {
    if out.len() >= max {
        return;
    }
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                walk_json(out, child, &format!("{path}.{k}"), max);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                walk_json(out, child, &format!("{path}[{i}]"), max);
            }
        }
        serde_json::Value::String(s) => {
            out.push(ParamUnit {
                path: path.into(),
                value: s.clone(),
                source: "json".into(),
            });
        }
        serde_json::Value::Number(n) => {
            out.push(ParamUnit {
                path: path.into(),
                value: n.to_string(),
                source: "json".into(),
            });
        }
        serde_json::Value::Bool(b) => {
            out.push(ParamUnit {
                path: path.into(),
                value: b.to_string(),
                source: "json".into(),
            });
        }
        serde_json::Value::Null => {}
    }
}

fn push_multipart(out: &mut Vec<ParamUnit>, body: &str, max: usize) {
    // 归一换行后按 boundary 分段，再拆 header / body
    let norm = body.replace("\r\n", "\n");
    for part in norm.split("\n--") {
        if out.len() >= max {
            break;
        }
        let Some((header, value)) = part.split_once("\n\n") else {
            continue;
        };
        let name = capture_attr(header, "name");
        let filename = capture_attr(header, "filename");
        if let Some(f) = filename {
            out.push(ParamUnit {
                path: format!(
                    "multipart.{}.filename",
                    name.clone().unwrap_or_else(|| "file".into())
                ),
                value: f,
                source: "multipart".into(),
            });
        }
        if let Some(n) = name {
            let v: String = value
                .lines()
                .take_while(|l| !l.starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
                .chars()
                .take(4096)
                .collect();
            if !v.is_empty() {
                out.push(ParamUnit {
                    path: format!("multipart.{n}"),
                    value: v,
                    source: "multipart".into(),
                });
            }
        }
    }
}

fn capture_attr(header: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let idx = header.find(&pat)?;
    let rest = &header[idx + pat.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
