//! aho-corasick 后端。

use super::PatternBackend;
use std::sync::Arc;

#[derive(Debug)]
pub struct AhoBackend {
    ac: Arc<aho_corasick::AhoCorasick>,
}

impl AhoBackend {
    pub fn try_build(patterns: &[String]) -> Option<Self> {
        if patterns.is_empty() {
            return None;
        }
        aho_corasick::AhoCorasick::new(patterns)
            .ok()
            .map(|ac| Self { ac: Arc::new(ac) })
    }
}

impl PatternBackend for AhoBackend {
    fn find_all(&self, haystack: &str) -> Vec<usize> {
        let mut out: Vec<usize> = self
            .ac
            .find_iter(haystack)
            .map(|m| m.pattern().as_usize())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}
