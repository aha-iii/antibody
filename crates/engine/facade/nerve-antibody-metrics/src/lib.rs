//! Native Engine 运行时指标（原子计数，无外部依赖）。
//!
//! Dashboard / WAF 可通过 [`global()`] 读取并暴露 `/metrics`（Prometheus text）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

static GLOBAL: OnceLock<EngineMetrics> = OnceLock::new();

pub fn global() -> &'static EngineMetrics {
    GLOBAL.get_or_init(EngineMetrics::new)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectPath {
    Fast,
    Deep,
}

impl InspectPath {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Deep => "deep",
        }
    }
}

/// Nerve RIS 风险分区（只分流，不定罪）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RisZone {
    /// 高置信干净 → Arc Fast
    #[default]
    Clean,
    /// 不确定 → Fast + escalate / Shadow
    Gray,
    /// 高风险或硬触发 → Cortex Deep
    Hot,
}

impl RisZone {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Gray => "gray",
            Self::Hot => "hot",
        }
    }
}

/// 热路径分阶段耗时（微秒，单次 inspect 累加）。
#[derive(Debug, Clone, Copy, Default)]
pub struct InspectStages {
    pub decode_us: u64,
    pub aho_us: u64,
    pub regex_us: u64,
    pub semantic_us: u64,
    pub fusion_us: u64,
}

pub struct InspectTimer {
    path: InspectPath,
    start: Instant,
}

impl InspectTimer {
    pub fn start(path: InspectPath) -> Self {
        Self {
            path,
            start: Instant::now(),
        }
    }

    /// 记录全局指标并返回本次耗时（微秒）。
    pub fn finish(self, metrics: &EngineMetrics, budget_exhausted: bool, blocked: bool) -> u64 {
        let us = self.start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        metrics.record_inspect(self.path, us, budget_exhausted, blocked);
        us
    }
}

const LATENCY_BUCKET_US: [u64; 7] = [1_000, 5_000, 20_000, 50_000, 200_000, 1_200_000, u64::MAX];

pub struct EngineMetrics {
    inspect_total: AtomicU64,
    inspect_fast: AtomicU64,
    ris_zone_clean: AtomicU64,
    ris_zone_gray: AtomicU64,
    ris_zone_hot: AtomicU64,
    inspect_deep: AtomicU64,
    inspect_hit: AtomicU64,
    inspect_block: AtomicU64,
    inspect_challenge: AtomicU64,
    inspect_observe: AtomicU64,
    budget_exhausted: AtomicU64,
    latency_us_sum: AtomicU64,
    latency_us_max: AtomicU64,
    latency_fast_us_sum: AtomicU64,
    latency_deep_us_sum: AtomicU64,
    latency_buckets: [AtomicU64; LATENCY_BUCKET_US.len()],
    route_gate_total: AtomicU64,
    route_gate_deep: AtomicU64,
    stage_decode_us_sum: AtomicU64,
    stage_aho_us_sum: AtomicU64,
    stage_regex_us_sum: AtomicU64,
    stage_semantic_us_sum: AtomicU64,
    stage_fusion_us_sum: AtomicU64,
    shadow_done: AtomicU64,
    shadow_would_hit: AtomicU64,
    shadow_dropped: AtomicU64,
    fast_pool_escalate: AtomicU64,
    rule_hits: Mutex<HashMap<String, u64>>,
}

impl EngineMetrics {
    pub fn new() -> Self {
        Self {
            inspect_total: AtomicU64::new(0),
            inspect_fast: AtomicU64::new(0),
            ris_zone_clean: AtomicU64::new(0),
            ris_zone_gray: AtomicU64::new(0),
            ris_zone_hot: AtomicU64::new(0),
            inspect_deep: AtomicU64::new(0),
            inspect_hit: AtomicU64::new(0),
            inspect_block: AtomicU64::new(0),
            inspect_challenge: AtomicU64::new(0),
            inspect_observe: AtomicU64::new(0),
            budget_exhausted: AtomicU64::new(0),
            latency_us_sum: AtomicU64::new(0),
            latency_us_max: AtomicU64::new(0),
            latency_fast_us_sum: AtomicU64::new(0),
            latency_deep_us_sum: AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            route_gate_total: AtomicU64::new(0),
            route_gate_deep: AtomicU64::new(0),
            stage_decode_us_sum: AtomicU64::new(0),
            stage_aho_us_sum: AtomicU64::new(0),
            stage_regex_us_sum: AtomicU64::new(0),
            stage_semantic_us_sum: AtomicU64::new(0),
            stage_fusion_us_sum: AtomicU64::new(0),
            shadow_done: AtomicU64::new(0),
            shadow_would_hit: AtomicU64::new(0),
            shadow_dropped: AtomicU64::new(0),
            fast_pool_escalate: AtomicU64::new(0),
            rule_hits: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_fast_pool_escalate(&self) {
        self.fast_pool_escalate.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_inspect(
        &self,
        path: InspectPath,
        elapsed_us: u64,
        budget_exhausted: bool,
        blocked: bool,
    ) {
        self.inspect_total.fetch_add(1, Ordering::Relaxed);
        match path {
            InspectPath::Fast => {
                self.inspect_fast.fetch_add(1, Ordering::Relaxed);
                self.latency_fast_us_sum
                    .fetch_add(elapsed_us, Ordering::Relaxed);
            }
            InspectPath::Deep => {
                self.inspect_deep.fetch_add(1, Ordering::Relaxed);
                self.latency_deep_us_sum
                    .fetch_add(elapsed_us, Ordering::Relaxed);
            }
        }
        self.latency_us_sum.fetch_add(elapsed_us, Ordering::Relaxed);
        self.update_max(elapsed_us);
        self.record_latency_bucket(elapsed_us);
        if budget_exhausted {
            self.budget_exhausted.fetch_add(1, Ordering::Relaxed);
        }
        // hit = 拦截类动作（block|challenge）；细粒度 block/challenge/observe 见 record_action
        if blocked {
            self.inspect_hit.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fusion 后动作计数：`block` / `challenge` / `observe`。
    pub fn record_action(&self, action: &str) {
        match action {
            "block" => {
                self.inspect_block.fetch_add(1, Ordering::Relaxed);
            }
            "challenge" => {
                self.inspect_challenge.fetch_add(1, Ordering::Relaxed);
            }
            "observe" | "log" => {
                self.inspect_observe.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    pub fn record_route_gate(&self, route_deep: bool, _score: f32) {
        self.route_gate_total.fetch_add(1, Ordering::Relaxed);
        if route_deep {
            self.route_gate_deep.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_ris_zone(&self, zone: RisZone) {
        match zone {
            RisZone::Clean => {
                self.ris_zone_clean.fetch_add(1, Ordering::Relaxed);
            }
            RisZone::Gray => {
                self.ris_zone_gray.fetch_add(1, Ordering::Relaxed);
            }
            RisZone::Hot => {
                self.ris_zone_hot.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_stages(&self, s: &InspectStages) {
        self.stage_decode_us_sum
            .fetch_add(s.decode_us, Ordering::Relaxed);
        self.stage_aho_us_sum.fetch_add(s.aho_us, Ordering::Relaxed);
        self.stage_regex_us_sum
            .fetch_add(s.regex_us, Ordering::Relaxed);
        self.stage_semantic_us_sum
            .fetch_add(s.semantic_us, Ordering::Relaxed);
        self.stage_fusion_us_sum
            .fetch_add(s.fusion_us, Ordering::Relaxed);
    }

    pub fn record_shadow_done(&self, would_hit: bool) {
        self.shadow_done.fetch_add(1, Ordering::Relaxed);
        if would_hit {
            self.shadow_would_hit.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_shadow_drop(&self) {
        self.shadow_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rule_hit(&self, rule_id: &str) {
        if rule_id.is_empty() {
            return;
        }
        if let Ok(mut g) = self.rule_hits.lock() {
            *g.entry(rule_id.to_string()).or_insert(0) += 1;
        }
    }

    fn record_latency_bucket(&self, us: u64) {
        for (i, cap) in LATENCY_BUCKET_US.iter().enumerate() {
            if us <= *cap {
                self.latency_buckets[i].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    fn update_max(&self, us: u64) {
        let mut cur = self.latency_us_max.load(Ordering::Relaxed);
        while us > cur {
            match self.latency_us_max.compare_exchange_weak(
                cur,
                us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
    }

    pub fn top_rules(&self, limit: usize) -> Vec<(String, u64)> {
        let Ok(g) = self.rule_hits.lock() else {
            return Vec::new();
        };
        let mut rows: Vec<_> = g.iter().map(|(k, v)| (k.clone(), *v)).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let total = self.inspect_total.load(Ordering::Relaxed);
        MetricsSnapshot {
            inspect_total: total,
            inspect_fast: self.inspect_fast.load(Ordering::Relaxed),
            ris_zone_clean: self.ris_zone_clean.load(Ordering::Relaxed),
            ris_zone_gray: self.ris_zone_gray.load(Ordering::Relaxed),
            ris_zone_hot: self.ris_zone_hot.load(Ordering::Relaxed),
            inspect_deep: self.inspect_deep.load(Ordering::Relaxed),
            inspect_hit: self.inspect_hit.load(Ordering::Relaxed),
            inspect_block: self.inspect_block.load(Ordering::Relaxed),
            inspect_challenge: self.inspect_challenge.load(Ordering::Relaxed),
            inspect_observe: self.inspect_observe.load(Ordering::Relaxed),
            budget_exhausted: self.budget_exhausted.load(Ordering::Relaxed),
            latency_us_sum: self.latency_us_sum.load(Ordering::Relaxed),
            latency_us_max: self.latency_us_max.load(Ordering::Relaxed),
            latency_fast_us_sum: self.latency_fast_us_sum.load(Ordering::Relaxed),
            latency_deep_us_sum: self.latency_deep_us_sum.load(Ordering::Relaxed),
            latency_buckets: self
                .latency_buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
            route_gate_total: self.route_gate_total.load(Ordering::Relaxed),
            route_gate_deep: self.route_gate_deep.load(Ordering::Relaxed),
            stage_decode_us_avg: avg_stage(self.stage_decode_us_sum.load(Ordering::Relaxed), total),
            stage_aho_us_avg: avg_stage(self.stage_aho_us_sum.load(Ordering::Relaxed), total),
            stage_regex_us_avg: avg_stage(self.stage_regex_us_sum.load(Ordering::Relaxed), total),
            stage_semantic_us_avg: avg_stage(
                self.stage_semantic_us_sum.load(Ordering::Relaxed),
                total,
            ),
            stage_fusion_us_avg: avg_stage(self.stage_fusion_us_sum.load(Ordering::Relaxed), total),
            shadow_done: self.shadow_done.load(Ordering::Relaxed),
            shadow_would_hit: self.shadow_would_hit.load(Ordering::Relaxed),
            shadow_dropped: self.shadow_dropped.load(Ordering::Relaxed),
            fast_pool_escalate: self.fast_pool_escalate.load(Ordering::Relaxed),
            top_rules: self.top_rules(20),
        }
    }

    pub fn render_prometheus(&self) -> String {
        let s = self.snapshot();
        let avg_us = if s.inspect_total > 0 {
            s.latency_us_sum / s.inspect_total
        } else {
            0
        };
        let fast_avg = if s.inspect_fast > 0 {
            s.latency_fast_us_sum / s.inspect_fast
        } else {
            0
        };
        let deep_avg = if s.inspect_deep > 0 {
            s.latency_deep_us_sum / s.inspect_deep
        } else {
            0
        };
        let fast_pct = pct(s.inspect_fast, s.inspect_total);
        let deep_pct = pct(s.inspect_deep, s.inspect_total);
        let budget_pct = pct(s.budget_exhausted, s.inspect_total);
        let route_deep_pct = pct(s.route_gate_deep, s.route_gate_total.max(1));

        let mut out = format!(
            "# HELP nerve_native_inspect_total Total inspect calls\n\
             # TYPE nerve_native_inspect_total counter\n\
             nerve_native_inspect_total {}\n\
             nerve_native_inspect_fast_total {}\n\
             nerve_native_ris_zone_clean_total {}\n\
             nerve_native_ris_zone_gray_total {}\n\
             nerve_native_ris_zone_hot_total {}\n\
             nerve_native_inspect_deep_total {}\n\
             nerve_native_inspect_hit_total {}\n\
             nerve_native_inspect_block_total {}\n\
             nerve_native_inspect_challenge_total {}\n\
             nerve_native_inspect_observe_total {}\n\
             nerve_native_budget_exhausted_total {}\n\
             nerve_native_inspect_latency_us_avg {}\n\
             nerve_native_inspect_latency_us_max {}\n\
             nerve_native_inspect_fast_latency_us_avg {}\n\
             nerve_native_inspect_deep_latency_us_avg {}\n\
             nerve_native_inspect_fast_ratio {:.4}\n\
             nerve_native_inspect_deep_ratio {:.4}\n\
             nerve_native_budget_exhausted_ratio {:.4}\n\
             nerve_native_route_gate_deep_ratio {:.4}\n\
             nerve_native_stage_decode_us_avg {}\n\
             nerve_native_stage_aho_us_avg {}\n\
             nerve_native_stage_regex_us_avg {}\n\
             nerve_native_stage_semantic_us_avg {}\n\
             nerve_native_stage_fusion_us_avg {}\n\
             nerve_native_shadow_deep_total {}\n\
             nerve_native_shadow_would_hit_total {}\n\
             nerve_native_shadow_dropped_total {}\n\
             nerve_native_fast_pool_escalate_total {}\n",
            s.inspect_total,
            s.inspect_fast,
            s.ris_zone_clean,
            s.ris_zone_gray,
            s.ris_zone_hot,
            s.inspect_deep,
            s.inspect_hit,
            s.inspect_block,
            s.inspect_challenge,
            s.inspect_observe,
            s.budget_exhausted,
            avg_us,
            s.latency_us_max,
            fast_avg,
            deep_avg,
            fast_pct,
            deep_pct,
            budget_pct,
            route_deep_pct,
            s.stage_decode_us_avg,
            s.stage_aho_us_avg,
            s.stage_regex_us_avg,
            s.stage_semantic_us_avg,
            s.stage_fusion_us_avg,
            s.shadow_done,
            s.shadow_would_hit,
            s.shadow_dropped,
            s.fast_pool_escalate,
        );

        let labels = [
            "le_1ms",
            "le_5ms",
            "le_20ms",
            "le_50ms",
            "le_200ms",
            "le_1200ms",
            "le_inf",
        ];
        for (label, count) in labels.iter().zip(s.latency_buckets.iter()) {
            out.push_str(&format!(
                "nerve_native_inspect_latency_bucket{{le=\"{}\"}} {}\n",
                label, count
            ));
        }
        for (rule_id, count) in &s.top_rules {
            let esc = rule_id.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!(
                "nerve_native_rule_hits_total{{rule_id=\"{}\"}} {}\n",
                esc, count
            ));
        }
        out
    }
}

fn pct(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

fn avg_stage(sum: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        sum / total
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub inspect_total: u64,
    pub inspect_fast: u64,
    pub ris_zone_clean: u64,
    pub ris_zone_gray: u64,
    pub ris_zone_hot: u64,
    pub inspect_deep: u64,
    pub inspect_hit: u64,
    pub inspect_block: u64,
    pub inspect_challenge: u64,
    pub inspect_observe: u64,
    pub budget_exhausted: u64,
    pub latency_us_sum: u64,
    pub latency_us_max: u64,
    pub latency_fast_us_sum: u64,
    pub latency_deep_us_sum: u64,
    pub latency_buckets: Vec<u64>,
    pub route_gate_total: u64,
    pub route_gate_deep: u64,
    pub stage_decode_us_avg: u64,
    pub stage_aho_us_avg: u64,
    pub stage_regex_us_avg: u64,
    pub stage_semantic_us_avg: u64,
    pub stage_fusion_us_avg: u64,
    pub shadow_done: u64,
    pub shadow_would_hit: u64,
    pub shadow_dropped: u64,
    pub fast_pool_escalate: u64,
    pub top_rules: Vec<(String, u64)>,
}

pub fn duration_us(d: Duration) -> u64 {
    d.as_micros().min(u128::from(u64::MAX)) as u64
}
