//! Deep 路径 decode 视图 LRU 抽象（实现由 engine 注入，runtime 不依赖 cache crate）。

use nerve_antibody_pipeline::RequestViews;

/// Decode LRU 键：path 指纹 + payload 前缀 hash + 解码深度。
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DeepViewCacheKey {
    pub path_fp: u64,
    pub payload_hash: u64,
    pub max_depth: u8,
}

/// Deep-only 视图缓存（JSON 序列化由实现方负责）。
pub trait DeepViewCache: Send + Sync {
    fn lookup(&self, key: &DeepViewCacheKey) -> Option<RequestViews>;
    fn store(&self, key: &DeepViewCacheKey, views: &RequestViews);
}

pub fn payload_hash(query: &str, body: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    query.hash(&mut h);
    body.as_bytes().iter().take(4096).for_each(|b| b.hash(&mut h));
    h.finish()
}
