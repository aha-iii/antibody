//! Deep 路径 decode 视图 LRU（按 body/query 前缀 hash）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DecodeLruKey {
    pub path_fp: u64,
    pub payload_hash: u64,
    pub max_depth: u8,
}

#[derive(Debug)]
struct Entry {
    blob: Vec<u8>,
    expires: Instant,
}

#[derive(Debug)]
pub struct DecodeLru {
    ttl: Duration,
    capacity: usize,
    map: HashMap<DecodeLruKey, Entry>,
    order: Vec<DecodeLruKey>,
}

impl DecodeLru {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            capacity: capacity.max(32),
            map: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn get(&mut self, key: &DecodeLruKey) -> Option<Vec<u8>> {
        let ent = self.map.get(key)?;
        if Instant::now() >= ent.expires {
            self.map.remove(key);
            return None;
        }
        Some(ent.blob.clone())
    }

    pub fn put(&mut self, key: DecodeLruKey, blob: Vec<u8>) {
        let exp = Instant::now() + self.ttl;
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, Entry { blob, expires: exp });
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
