//! Fast 干净判定负向缓存（短 TTL）。

use crate::CachedVerdict;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 负向缓存键：模板化路径 + 信号位（不含 sign 值）。
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct NegativeCacheKey {
    pub method: String,
    pub path_template: String,
    pub signal_bits: u64,
    pub body_len_bucket: u32,
}

impl NegativeCacheKey {
    pub fn new(method: &str, path_template: &str, signal_bits: u64, body_len: usize) -> Self {
        Self {
            method: method.to_ascii_uppercase(),
            path_template: path_template.to_string(),
            signal_bits,
            body_len_bucket: (body_len / 256).min(255) as u32,
        }
    }
}

#[derive(Debug)]
pub struct NegativeCache {
    ttl: Duration,
    map: HashMap<NegativeCacheKey, Instant>,
    order: Vec<NegativeCacheKey>,
    capacity: usize,
}

impl NegativeCache {
    /// 清空负向缓存。用于规则包 reload、策略切换或测试隔离。
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            map: HashMap::new(),
            order: Vec::new(),
            capacity: capacity.max(64),
        }
    }

    pub fn get(&mut self, key: &NegativeCacheKey) -> Option<CachedVerdict> {
        let exp = self.map.get(key).copied()?;
        if Instant::now() >= exp {
            self.map.remove(key);
            return None;
        }
        Some(CachedVerdict {
            allowed: true,
            expires: exp,
        })
    }

    pub fn put(&mut self, key: NegativeCacheKey) {
        let exp = Instant::now() + self.ttl;
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, exp);
        while self.map.len() > self.capacity {
            if let Some(old) = self.order.first().cloned() {
                self.order.remove(0);
                self.map.remove(&old);
            } else {
                break;
            }
        }
    }
}
