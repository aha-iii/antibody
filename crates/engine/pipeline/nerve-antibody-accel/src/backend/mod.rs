//! 加速后端抽象。

#[cfg(feature = "aho")]
mod aho;
#[cfg(feature = "accel-hyperscan")]
mod hyperscan;
#[cfg(feature = "accel-hyperscan-ffi")]
mod hyperscan_ffi;
mod linear;

use std::sync::Arc;

/// 当前二进制实际启用的加速后端。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelKind {
    None,
    AhoCorasick,
    #[cfg(feature = "accel-hyperscan")]
    Hyperscan,
}

/// 探测编译期 feature。
pub fn available() -> AccelKind {
    #[cfg(feature = "accel-hyperscan")]
    {
        return AccelKind::Hyperscan;
    }
    #[cfg(all(feature = "aho", not(feature = "accel-hyperscan")))]
    {
        return AccelKind::AhoCorasick;
    }
    #[allow(unreachable_code)]
    AccelKind::None
}

/// 多模匹配器（编译期建一次）。
#[derive(Debug, Clone)]
pub struct MultiMatcher {
    patterns: Vec<String>,
    inner: Arc<dyn PatternBackend>,
}

trait PatternBackend: Send + Sync + std::fmt::Debug {
    fn find_all(&self, haystack: &str) -> Vec<usize>;
}

impl MultiMatcher {
    pub fn build(patterns: &[String]) -> Self {
        let patterns: Vec<String> = patterns
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect();

        #[cfg(all(feature = "accel-hyperscan", feature = "accel-hyperscan-ffi"))]
        let inner: Arc<dyn PatternBackend> =
            match hyperscan_ffi::HsFfiBackend::try_build(&patterns) {
                // 取 inner：FFI 模块不直接 impl PatternBackend（规避 rustc 1.93 ICE）
                Ok(hs) => Arc::new(hs.inner),
                Err(_) => fallback_backend(&patterns),
            };

        #[cfg(all(feature = "accel-hyperscan", not(feature = "accel-hyperscan-ffi")))]
        let inner: Arc<dyn PatternBackend> = match hyperscan::HsBackend::try_build(&patterns) {
            Ok(hs) => Arc::new(hs),
            Err(_) => fallback_backend(&patterns),
        };

        #[cfg(not(feature = "accel-hyperscan"))]
        let inner = fallback_backend(&patterns);

        Self { patterns, inner }
    }

    pub fn find(&self, haystack: &str) -> Option<usize> {
        self.find_all(haystack).into_iter().next()
    }

    pub fn find_all(&self, haystack: &str) -> Vec<usize> {
        self.inner.find_all(haystack)
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

fn fallback_backend(patterns: &[String]) -> Arc<dyn PatternBackend> {
    #[cfg(feature = "aho")]
    {
        if let Some(b) = aho::AhoBackend::try_build(patterns) {
            return Arc::new(b);
        }
    }
    Arc::new(linear::LinearBackend::new(patterns.to_vec()))
}
