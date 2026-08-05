//! 线性扫描回退。

use super::PatternBackend;

#[derive(Debug)]
pub struct LinearBackend {
    patterns: Vec<String>,
}

impl LinearBackend {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }
}

impl PatternBackend for LinearBackend {
    fn find_all(&self, haystack: &str) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, p) in self.patterns.iter().enumerate() {
            if !p.is_empty() && haystack.contains(p.as_str()) {
                out.push(i);
            }
        }
        out
    }
}
