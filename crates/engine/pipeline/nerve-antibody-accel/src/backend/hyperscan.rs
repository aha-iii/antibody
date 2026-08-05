//! Hyperscan 风格多模后端。
//!
//! 默认用 `regex::RegexSet` 对字面量字典做一次扫描（跨平台、无原生 HS 依赖）。
//! 原生 Hyperscan / Vectorscan FFI 可替换 [`HsBackend::try_build`] 内部实现，
//! 保持 [`super::PatternBackend`] 接口不变。

use super::PatternBackend;
use regex::RegexSet;

#[derive(Debug)]
pub struct HsBackend {
    set: RegexSet,
    /// RegexSet 模式下标 → 原始字典下标（过滤非法 pattern 后可能压缩）。
    map: Vec<usize>,
}

impl HsBackend {
    pub fn try_build(patterns: &[String]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Err("empty".into());
        }
        let mut escaped = Vec::new();
        let mut map = Vec::new();
        for (i, p) in patterns.iter().enumerate() {
            if p.is_empty() {
                continue;
            }
            // 字面量转义，等价于 Hyperscan literal 模式
            escaped.push(regex::escape(p));
            map.push(i);
        }
        if escaped.is_empty() {
            return Err("no patterns".into());
        }
        let set = RegexSet::new(&escaped).map_err(|e| e.to_string())?;
        Ok(Self { set, map })
    }
}

impl PatternBackend for HsBackend {
    fn find_all(&self, haystack: &str) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .set
            .matches(haystack)
            .into_iter()
            .filter_map(|i| self.map.get(i).copied())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}
