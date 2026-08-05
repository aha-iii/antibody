//! # nerve-antibody-accel
//!
//! 多模字符串加速层（分层后端）：
//!
//! - **aho**（默认）：`aho-corasick`
//! - **accel-hyperscan**：Hyperscan 风格多模路径（RegexSet 字面量加速；可换原生 HS FFI）
//! - 无 feature：线性 `contains`

mod backend;

pub use backend::{available, AccelKind, MultiMatcher};

/// 一次性扫描（无预构建场景）。
pub fn multi_find(haystack: &str, patterns: &[&str]) -> Option<usize> {
    let owned: Vec<String> = patterns.iter().map(|s| (*s).to_string()).collect();
    MultiMatcher::build(&owned).find(haystack)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_script() {
        let m = MultiMatcher::build(&["<script".into(), "union select".into()]);
        assert_eq!(m.find("x=<script>y"), Some(0));
        let all = m.find_all("union select <script>");
        assert!(all.contains(&0) && all.contains(&1));
    }
}
