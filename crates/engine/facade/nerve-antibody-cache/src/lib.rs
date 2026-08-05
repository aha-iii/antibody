//! 检测热路径缓存层（与 block 裁决解耦，仅加速重复干净流量）。
//!
//! | 模块 | 用途 |
//! |------|------|
//! | [`bloom`] | 高置信干净 Bloom 前置（可能脏 → 正常路由） |
//! | [`negative`] | Fast 干净判定短 TTL 负向缓存 |
//! | [`decode_lru`] | Deep 路径 decode 视图 LRU |
//! | [`VerdictCache`] | 统一门面 |

mod bloom;
mod decode_lru;
mod negative;
mod policy;

pub use bloom::ClearBloom;
pub use decode_lru::{DecodeLru, DecodeLruKey};
pub use negative::{NegativeCache, NegativeCacheKey};
pub use policy::CachePolicy;

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 负向缓存条目：上次 Fast 无 block。
#[derive(Debug, Clone, Copy)]
pub struct CachedVerdict {
    pub allowed: bool,
    pub expires: Instant,
}

/// 进程级 inspect 缓存门面。
#[derive(Clone)]
pub struct VerdictCache {
    policy: CachePolicy,
    negative: Arc<Mutex<NegativeCache>>,
    bloom: Arc<Mutex<ClearBloom>>,
    decode: Arc<Mutex<DecodeLru>>,
}

impl VerdictCache {
    pub fn new(policy: CachePolicy) -> Self {
        Self {
            bloom: Arc::new(Mutex::new(ClearBloom::new(policy.bloom_bits, policy.bloom_k))),
            negative: Arc::new(Mutex::new(NegativeCache::new(
                policy.negative_capacity,
                Duration::from_secs(policy.negative_ttl_secs),
            ))),
            decode: Arc::new(Mutex::new(DecodeLru::new(
                policy.decode_lru_capacity,
                Duration::from_secs(policy.decode_lru_ttl_secs),
            ))),
            policy,
        }
    }

    pub fn from_env() -> Self {
        Self::new(CachePolicy::from_env())
    }

    pub fn policy(&self) -> &CachePolicy {
        &self.policy
    }

    /// Bloom 前置：true = 高置信干净，可 skip 部分路由打分（仍跑 L1）。
    pub fn bloom_maybe_clear(&self, key_hash: u64) -> bool {
        if !self.policy.bloom_enabled {
            return false;
        }
        self.bloom.lock().maybe_contains(key_hash)
    }

    pub fn bloom_train_clear(&self, key_hash: u64) {
        if self.policy.bloom_enabled {
            self.bloom.lock().insert(key_hash);
        }
    }

    pub fn negative_get(&self, key: &NegativeCacheKey) -> Option<CachedVerdict> {
        if !self.policy.negative_enabled {
            return None;
        }
        self.negative.lock().get(key)
    }

    pub fn negative_put(&self, key: NegativeCacheKey) {
        if self.policy.negative_enabled {
            self.negative.lock().put(key);
        }
    }

    pub fn decode_get(&self, key: &DecodeLruKey) -> Option<Vec<u8>> {
        if !self.policy.decode_lru_enabled {
            return None;
        }
        self.decode.lock().get(key)
    }

    pub fn decode_put(&self, key: DecodeLruKey, views_blob: Vec<u8>) {
        if self.policy.decode_lru_enabled {
            self.decode.lock().put(key, views_blob);
        }
    }
}

/// 由请求信号构造负向/Bloom 键（不含敏感 payload 原文）。
pub fn cache_key_hash(method: &str, path_template: &str, signal_bits: u64, body_len: usize) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    method.to_ascii_uppercase().hash(&mut h);
    path_template.hash(&mut h);
    signal_bits.hash(&mut h);
    body_len.hash(&mut h);
    h.finish()
}
