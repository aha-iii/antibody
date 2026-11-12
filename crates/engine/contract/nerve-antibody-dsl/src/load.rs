//! 从磁盘加载规则 YAML。

use crate::error::DslError;
use crate::types::NativeRule;
use std::fs;
use std::path::Path;

/// 跳过 BOM / 空白 / 整行 `#` 注释后的正文起点（用于判断列表 vs 单对象）。
fn content_start(text: &str) -> &str {
    let mut s = text.trim_start_matches('\u{feff}');
    loop {
        s = s.trim_start();
        if let Some(rest) = s.strip_prefix('#') {
            if let Some(nl) = rest.find('\n') {
                s = &rest[nl + 1..];
                continue;
            }
            return "";
        }
        return s;
    }
}

/// 读规则/语义 YAML：去掉 `\r` 与其余 C0 控制符（保留 TAB/LF）。
/// WSL + `/mnt/d` 上常见 CRLF；serde_yaml 对原始控制符会报错。
pub fn read_yaml_file_text(path: impl AsRef<Path>) -> Result<String, DslError> {
    let path = path.as_ref();
    let bytes = fs::read(path)?;
    let mut out = Vec::with_capacity(bytes.len());
    for &b in &bytes {
        match b {
            b'\t' | b'\n' => out.push(b),
            b'\r' | 0..=8 | 11..=12 | 14..=31 => {}
            _ => out.push(b),
        }
    }
    String::from_utf8(out).map_err(|e| {
        DslError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: invalid utf-8: {e}", path.display()),
        ))
    })
}

/// 兼容旧调用：对已读入内存的文本做同样规范化。
pub fn normalize_yaml_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch == '\t' || ch == '\n' {
            out.push(ch);
        } else if ch.is_control() {
            continue;
        } else {
            out.push(ch);
        }
    }
    out
}

/// 读取一个 `.yaml` / `.yml` 文件为规则列表。
///
/// - 正文（跳过文件头注释后）以 `-` 开头 → 按 **数组** 解析
/// - 否则 → 按 **单对象** 解析（demo 单文件单规则）
///
/// 每条规则都会调用 [`NativeRule::validate`]。
pub fn load_rule_file(path: impl AsRef<Path>) -> Result<Vec<NativeRule>, DslError> {
    let path = path.as_ref();
    let text = read_yaml_file_text(path)?;
    let body = content_start(&text);
    if body.starts_with('-') {
        let list: Vec<NativeRule> = serde_yaml::from_str(&text)?;
        for r in &list {
            r.validate()?;
        }
        return Ok(list);
    }
    let one: NativeRule = serde_yaml::from_str(&text).map_err(|e| DslError::Invalid {
        id: path.display().to_string(),
        msg: format!("yaml: {e}"),
    })?;
    one.validate()?;
    Ok(vec![one])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn load_list_with_header_comments() {
        let dir = std::env::temp_dir();
        let path = dir.join("nerve-expert-dsl-commented-list.yaml");
        {
            let mut f = fs::File::create(&path).unwrap();
            write!(
                f,
                "# header\n# more\n\n- id: a\n  name: A\n  when:\n    any:\n      - field: uri\n        contains: x\n"
            )
            .unwrap();
        }
        let rules = load_rule_file(&path).expect("load commented list");
        let _ = fs::remove_file(&path);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "a");
    }

    #[test]
    fn content_start_skips_hash_comments() {
        let s = content_start("# a\n# b\n\n- id: x\n");
        assert!(s.starts_with('-'));
    }

    #[test]
    fn load_baseline_allow_rule() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packs/baseline/rules/00-allow/allow-adobe-activityi-cat.yaml");
        if !path.is_file() {
            return;
        }
        let rules = load_rule_file(&path).expect("allow-adobe");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "allow-adobe-activityi-cat");
    }

    #[test]
    fn load_crlf_yaml() {
        let path = std::env::temp_dir().join("nerve-expert-dsl-crlf.yaml");
        std::fs::write(
            &path,
            "- id: crlf\r\n  name: CR\r\n  when:\r\n    any:\r\n      - field: uri\r\n        contains: x\r\n",
        )
        .unwrap();
        let rules = load_rule_file(&path).expect("load crlf");
        let _ = std::fs::remove_file(&path);
        assert_eq!(rules[0].id, "crlf");
    }
}
