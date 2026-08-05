//! 缓存策略（环境变量 + 默认）。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePolicy {
    pub negative_enabled: bool,
    pub negative_ttl_secs: u64,
    pub negative_capacity: usize,
    pub bloom_enabled: bool,
    pub bloom_bits: usize,
    pub bloom_k: u32,
    pub decode_lru_enabled: bool,
    pub decode_lru_capacity: usize,
    pub decode_lru_ttl_secs: u64,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            negative_enabled: true,
            negative_ttl_secs: 30,
            negative_capacity: 8192,
            bloom_enabled: true,
            bloom_bits: 1 << 18,
            bloom_k: 4,
            decode_lru_enabled: true,
            decode_lru_capacity: 512,
            decode_lru_ttl_secs: 60,
        }
    }
}

impl CachePolicy {
    pub fn from_env() -> Self {
        let mut p = Self::default();
        if env_bool("NERVE_NATIVE_CACHE_NEGATIVE", true) {
            p.negative_enabled = true;
        } else {
            p.negative_enabled = false;
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_CACHE_NEGATIVE_TTL_SECS") {
            if let Ok(e) = v.parse::<u64>() {
                p.negative_ttl_secs = e.clamp(5, 300);
            }
        }
        if env_bool("NERVE_NATIVE_CACHE_BLOOM", true) {
            p.bloom_enabled = true;
        } else {
            p.bloom_enabled = false;
        }
        if env_bool("NERVE_NATIVE_CACHE_DECODE_LRU", true) {
            p.decode_lru_enabled = true;
        } else {
            p.decode_lru_enabled = false;
        }
        p
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key).as_deref() {
        Ok("0") | Ok("false") | Ok("off") | Ok("no") => false,
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => true,
        Ok(_) => default,
        Err(_) => default,
    }
}
