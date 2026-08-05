//! 轻量 SOAP/XML 拆参：提取标签 LocalName 与文本节点，不做完整 XPath / DOM。
//! 无第三方 XML 依赖；畸形输入软失败（返回已提取部分）。

use crate::views::ParamUnit;
use std::collections::BTreeMap;

/// 单标签文本与全局拼接上限。
const MAX_TAG_CHARS: usize = 4096;
const MAX_CONCAT_CHARS: usize = 8192;

/// Content-Type 或正文前缀是否像 XML/SOAP。
pub fn looks_like_xml(content_type: &str, body: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("application/xml")
        || ct.contains("text/xml")
        || ct.contains("+xml")
        || ct.contains("soap")
    {
        return true;
    }
    let head: String = body
        .trim_start()
        .chars()
        .take(80)
        .collect::<String>()
        .to_ascii_lowercase();
    head.starts_with("<?xml")
        || head.starts_with("<soap")
        || head.starts_with("<soapenv:")
        || head.starts_with("<soap-env:")
}

/// 将 XML/SOAP 正文拆为 ParamUnit（路径 `body.xml.tag:{LocalName}` / `body.xml.text`）。
pub fn push_xml(out: &mut Vec<ParamUnit>, body: &str, max: usize) {
    if body.is_empty() || out.len() >= max {
        return;
    }
    let extracted = extract_xml_light(body);
    for (local, text) in extracted.by_tag {
        if out.len() >= max {
            break;
        }
        if text.is_empty() {
            continue;
        }
        out.push(ParamUnit {
            path: format!("body.xml.tag:{local}"),
            value: text,
            source: "xml".into(),
        });
    }
    if out.len() < max && !extracted.concat_text.is_empty() {
        out.push(ParamUnit {
            path: "body.xml.text".into(),
            value: extracted.concat_text,
            source: "xml".into(),
        });
    }
}

#[derive(Default)]
struct Extracted {
    by_tag: BTreeMap<String, String>,
    concat_text: String,
}

fn extract_xml_light(body: &str) -> Extracted {
    let mut out = Extracted::default();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    // 当前开启元素栈（仅 LocalName）；用于把文本归到最近开标签。
    let mut stack: Vec<String> = Vec::new();

    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(next) = try_skip_or_take_markup(bytes, i, &mut out, &mut stack) {
                i = next;
                continue;
            }
            // 无法识别的 `<`：软失败，停止扫描
            break;
        }
        // 文本节点
        let start = i;
        while i < bytes.len() && bytes[i] != b'<' {
            i += 1;
        }
        if let Ok(text) = std::str::from_utf8(&bytes[start..i]) {
            push_text(&mut out, &stack, text);
        }
    }
    out
}

fn try_skip_or_take_markup(
    bytes: &[u8],
    i: usize,
    out: &mut Extracted,
    stack: &mut Vec<String>,
) -> Option<usize> {
    let rest = &bytes[i..];
    if rest.starts_with(b"<!--") {
        return find_after(bytes, i + 4, b"-->");
    }
    if rest.starts_with(b"<![CDATA[") {
        let start = i + 9;
        let end = find_bytes(bytes, start, b"]]>")?;
        if let Ok(text) = std::str::from_utf8(&bytes[start..end]) {
            push_text(out, stack, text);
        }
        return Some(end + 3);
    }
    if rest.starts_with(b"<?") {
        return find_after(bytes, i + 2, b"?>");
    }
    if rest.starts_with(b"<!") {
        // DOCTYPE / 其它声明：扫到下一个 `>`（不处理嵌套声明细节）
        return find_after(bytes, i + 2, b">");
    }
    // 普通开/闭/自闭合标签
    let close_angle = find_bytes(bytes, i + 1, b">")?;
    let inner = std::str::from_utf8(&bytes[i + 1..close_angle]).ok()?;
    let self_closing = inner.trim_end().ends_with('/');
    let name_part = inner.trim();
    if name_part.starts_with('/') {
        let raw = name_part[1..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        let local = local_name(raw);
        if !local.is_empty() {
            while let Some(top) = stack.last() {
                if top == &local {
                    stack.pop();
                    break;
                }
                // 错配时弹一层，继续软处理
                stack.pop();
            }
        }
        return Some(close_angle + 1);
    }
    let raw = name_part
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    let local = local_name(raw);
    if local.is_empty() {
        return Some(close_angle + 1);
    }
    if !self_closing {
        stack.push(local);
    } else {
        // 自闭合：登记空桶，便于规则按标签名探测存在性（无文本则 push_xml 会跳过）
        out.by_tag.entry(local).or_default();
    }
    Some(close_angle + 1)
}

fn local_name(qname: &str) -> String {
    let s = qname.trim();
    if s.is_empty() {
        return String::new();
    }
    match s.rsplit_once(':') {
        Some((_, local)) if !local.is_empty() => local.to_string(),
        _ => s.to_string(),
    }
}

fn push_text(out: &mut Extracted, stack: &[String], text: &str) {
    let trimmed_ws = if text.chars().all(|c| c.is_whitespace()) {
        return;
    } else {
        text
    };
    append_capped(&mut out.concat_text, trimmed_ws, MAX_CONCAT_CHARS);
    if let Some(tag) = stack.last() {
        let entry = out.by_tag.entry(tag.clone()).or_default();
        append_capped(entry, trimmed_ws, MAX_TAG_CHARS);
    }
}

fn append_capped(dst: &mut String, src: &str, max: usize) {
    if dst.len() >= max {
        return;
    }
    let remain = max - dst.len();
    let take = src.floor_char_boundary(remain.min(src.len()));
    dst.push_str(&src[..take]);
}

fn find_bytes(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

fn find_after(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    find_bytes(hay, from, needle).map(|p| p + needle.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_content_type_and_soap_prefix() {
        assert!(looks_like_xml("application/xml; charsett=utf-8", ""));
        assert!(looks_like_xml("text/xml", ""));
        assert!(looks_like_xml("", "<?xml version=\"1.0\"?><a/>"));
        assert!(looks_like_xml(
            "",
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"/>"
        ));
        assert!(!looks_like_xml("application/json", "{\"a\":1}"));
    }

    #[test]
    fn soap_envelope_extracts_script_like_text() {
        let body = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Submit>
      <data><![CDATA[<script>alert(1)</script>]]></data>
    </Submit>
  </soap:Body>
</soap:Envelope>"#;
        let mut out = Vec::new();
        push_xml(&mut out, body, 64);
        assert!(
            out.iter()
                .any(|p| p.path == "body.xml.tag:data"
                    && p.value.to_ascii_lowercase().contains("<script")),
            "expected body.xml.tag:data with script-like CDATA, got {out:?}"
        );
        assert!(
            out.iter()
                .any(|p| p.path == "body.xml.text"
                    && p.value.to_ascii_lowercase().contains("alert(1)")),
            "expected concat text, got {out:?}"
        );
    }

    #[test]
    fn malformed_xml_soft_fails() {
        let mut out = Vec::new();
        push_xml(&mut out, "<root><child>ok</child><<<<", 64);
        assert!(
            out.iter()
                .any(|p| p.path == "body.xml.tag:child" && p.value.contains("ok")),
            "partial extract expected, got {out:?}"
        );
    }
}
