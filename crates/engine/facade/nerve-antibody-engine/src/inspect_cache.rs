//! Inspect 负向/Bloom/结构记忆缓存与 Nerve RIS L1 探针。

use nerve_antibody_cache::{cache_key_hash, NegativeCacheKey, VerdictCache};
use nerve_antibody_runtime::{structure_fingerprint, NativeRequest, PlanCacheHints, RisL1Probe};
use nerve_antibody_signals::RequestSignals;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

static VERDICT_CACHE: OnceLock<Arc<VerdictCache>> = OnceLock::new();

pub fn global_verdict_cache() -> Arc<VerdictCache> {
    VERDICT_CACHE
        .get_or_init(|| Arc::new(VerdictCache::from_env()))
        .clone()
}

/// 清空进程级判定缓存。
///
/// 缓存 key 只含 `method + path_template + signal_bits + body_len`，不含规则包指纹
/// 与烈度等级，因此同一路径在不同 pack / level 下会共享判定。生产侧在 reload 后
/// 需要清空，测试侧在用例间需要清空，否则会出现「单跑通过、连跑失败」。
pub fn reset_global_verdict_cache() {
    global_verdict_cache().clear();
}

pub fn path_template(uri: &str) -> String {
    nerve_antibody_runtime::structure_path_template(uri)
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

/// per-route 学过的结构指纹（method+path_tpl → 键集合指纹）。
struct StructureMemory {
    by_route: HashMap<(String, String), HashSet<u64>>,
    capacity_routes: usize,
    capacity_fps_per_route: usize,
}

impl StructureMemory {
    fn new() -> Self {
        Self {
            by_route: HashMap::new(),
            capacity_routes: 4096,
            capacity_fps_per_route: 64,
        }
    }

    fn route_key(req: &NativeRequest) -> (String, String) {
        (req.method.to_ascii_uppercase(), path_template(&req.uri))
    }

    fn known(&self, req: &NativeRequest) -> bool {
        let rk = Self::route_key(req);
        let fp = structure_fingerprint(req);
        self.by_route
            .get(&rk)
            .map(|s| s.contains(&fp))
            .unwrap_or(false)
    }

    fn remember(&mut self, req: &NativeRequest) {
        let rk = Self::route_key(req);
        let fp = structure_fingerprint(req);
        if !self.by_route.contains_key(&rk) && self.by_route.len() >= self.capacity_routes {
            if let Some(old) = self.by_route.keys().next().cloned() {
                self.by_route.remove(&old);
            }
        }
        let set = self.by_route.entry(rk).or_default();
        if set.len() >= self.capacity_fps_per_route && !set.contains(&fp) {
            if let Some(old) = set.iter().next().copied() {
                set.remove(&old);
            }
        }
        set.insert(fp);
    }
}

/// Nerve RIS L1：挂到 `EvalPolicy.ris_l1`。
pub struct RisL1CacheProbe {
    cache: Arc<VerdictCache>,
    structures: Mutex<StructureMemory>,
}

impl RisL1CacheProbe {
    pub fn new(cache: Arc<VerdictCache>) -> Self {
        Self {
            cache,
            structures: Mutex::new(StructureMemory::new()),
        }
    }
}

impl RisL1Probe for RisL1CacheProbe {
    fn probe(&self, req: &NativeRequest, signals: &RequestSignals) -> PlanCacheHints {
        let bk = bloom_key(req, signals);
        let bloom_clear = self.cache.bloom_maybe_clear(bk);
        let negative_hit = if negative_cache_eligible(signals) {
            self.cache
                .negative_get(&negative_key(req, signals))
                .is_some()
        } else {
            false
        };
        let structure_known = self.structures.lock().known(req);
        PlanCacheHints {
            bloom_clear,
            negative_hit,
            structure_known,
        }
    }

    fn remember_clear(&self, req: &NativeRequest, signals: &RequestSignals) {
        self.cache.bloom_train_clear(bloom_key(req, signals));
        if negative_cache_eligible(signals) {
            self.cache.negative_put(negative_key(req, signals));
        }
        self.structures.lock().remember(req);
    }
}
