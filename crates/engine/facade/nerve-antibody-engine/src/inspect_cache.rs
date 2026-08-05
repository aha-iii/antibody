//! Inspect 负向/Bloom 缓存与 signals 键构造。

use nerve_antibody_cache::{cache_key_hash, NegativeCacheKey, VerdictCache};
use nerve_antibody_runtime::NativeRequest;
use nerve_antibody_signals::RequestSignals;
use std::sync::{Arc, OnceLock};

static VERDICT_CACHE: OnceLock<Arc<VerdictCache>> = OnceLock::new();

pub fn global_verdict_cache() -> Arc<VerdictCache> {
    VERDICT_CACHE
        .get_or_init(|| Arc::new(VerdictCache::from_env()))
        .clone()
}

pub fn path_template(uri: &str) -> String {
    uri.split('?')
        .next()
        .unwrap_or(uri)
        .split('/')
        .map(|seg| {
            if seg.is_empty() {
                return String::new();
            }
            if seg.bytes().all(|b| b.is_ascii_digit()) {
                "{d}".into()
            } else if seg.len() == 36 && seg.as_bytes().iter().filter(|&&b| b == b'-').count() == 4 {
                "{uuid}".into()
            } else {
                seg.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn signal_bits(signals: &RequestSignals) -> u64 {
    signals.path_fingerprint ^ signals.request_fingerprint
}

/// 仅 structured_json / hex_sign 准入负向缓存。
pub fn negative_cache_eligible(signals: &RequestSignals) -> bool {
    signals.feature("structured_json_body") || signals.feature("hex_sign_param")
}

pub fn negative_key(req: &NativeRequest, signals: &RequestSignals) -> NegativeCacheKey {
    NegativeCacheKey::new(
        &req.method,
        &path_template(&req.uri),
        signal_bits(signals),
        req.body.len(),
    )
}

pub fn bloom_key(req: &NativeRequest, signals: &RequestSignals) -> u64 {
    cache_key_hash(
        &req.method,
        &path_template(&req.uri),
        signal_bits(signals),
        req.body.len(),
    )
}
