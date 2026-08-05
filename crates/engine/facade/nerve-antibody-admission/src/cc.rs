//! CC / Rate：单机 token bucket（IP|Host|URI）。

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_rpm")]
    pub requests_per_minute: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default = "default_block_sec")]
    pub block_duration_sec: u64,
    #[serde(default = "default_cc_action")]
    pub action: String,
}

fn default_true() -> bool {
    true
}
fn default_rpm() -> u32 {
    120
}
fn default_burst() -> u32 {
    40
}
fn default_block_sec() -> u64 {
    300
}
fn default_cc_action() -> String {
    "challenge".into()
}

impl Default for CcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: default_rpm(),
            burst: default_burst(),
            block_duration_sec: default_block_sec(),
            action: default_cc_action(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CcCheckRequest {
    pub src_ip: String,
    pub host: String,
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcCheckResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_sec: Option<u64>,
    pub reason: Option<String>,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct CcEngine {
    config: Mutex<CcConfig>,
    buckets: Mutex<HashMap<String, Bucket>>,
    blocked: Mutex<HashMap<String, Instant>>,
}

impl CcEngine {
    pub fn new(config: CcConfig) -> Self {
        Self {
            config: Mutex::new(config),
            buckets: Mutex::new(HashMap::new()),
            blocked: Mutex::new(HashMap::new()),
        }
    }

    pub fn update_config(&self, config: CcConfig) {
        *self.config.lock() = config;
    }

    pub fn check(&self, req: &CcCheckRequest) -> CcCheckResult {
        let cfg = self.config.lock().clone();
        if !cfg.enabled {
            return CcCheckResult {
                allowed: true,
                remaining: cfg.requests_per_minute,
                retry_after_sec: None,
                reason: None,
            };
        }

        let key = format!("{}|{}|{}", req.src_ip, req.host, req.uri);
        {
            let mut blocked = self.blocked.lock();
            if let Some(at) = blocked.get(&key) {
                let elapsed = at.elapsed().as_secs();
                if elapsed < cfg.block_duration_sec {
                    return CcCheckResult {
                        allowed: false,
                        remaining: 0,
                        retry_after_sec: Some(cfg.block_duration_sec.saturating_sub(elapsed)),
                        reason: Some("cc_blocked".into()),
                    };
                }
                blocked.remove(&key);
            }
        }

        let limit = cfg.requests_per_minute.max(1) as f64;
        let burst = cfg.burst.max(1) as f64;
        let refill_per_sec = limit / 60.0;
        let now = Instant::now();

        let mut buckets = self.buckets.lock();
        let bucket = buckets.entry(key.clone()).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last = now;

        if bucket.tokens < 1.0 {
            if cfg.block_duration_sec > 0 {
                self.blocked.lock().insert(key, now);
            }
            return CcCheckResult {
                allowed: false,
                remaining: 0,
                retry_after_sec: Some(cfg.block_duration_sec.max(1)),
                reason: Some("cc_rate_exceeded".into()),
            };
        }
        bucket.tokens -= 1.0;
        CcCheckResult {
            allowed: true,
            remaining: bucket.tokens.floor() as u32,
            retry_after_sec: None,
            reason: None,
        }
    }
}
