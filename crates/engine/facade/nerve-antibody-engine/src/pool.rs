//! Fast/Deep 双 worker 池：隔离 CPU 争抢，快路径有界队列。

use nerve_antibody_metrics::InspectPath;
use nerve_antibody_runtime::{Evaluator, InspectPlan, NativeHit, NativeRequest, PlanCacheHints};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

/// 池配置（可由环境变量覆盖）。
#[derive(Debug, Clone)]
pub struct InspectPoolConfig {
    pub fast_workers: usize,
    pub deep_workers: usize,
    pub fast_queue: usize,
    pub deep_queue: usize,
    pub fast_timeout_ms: u64,
}

impl Default for InspectPoolConfig {
    fn default() -> Self {
        Self {
            fast_workers: 2,
            deep_workers: 4,
            fast_queue: 256,
            deep_queue: 128,
            // 与 baseline fast_max_inspect_ms(80) 对齐；过短会误升 deep（秒级）
            fast_timeout_ms: 150,
        }
    }
}

impl InspectPoolConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("NERVE_NATIVE_FAST_WORKERS") {
            if let Ok(n) = v.parse::<usize>() {
                c.fast_workers = n.clamp(1, 32);
            }
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_DEEP_WORKERS") {
            if let Ok(n) = v.parse::<usize>() {
                c.deep_workers = n.clamp(1, 32);
            }
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_FAST_QUEUE") {
            if let Ok(n) = v.parse::<usize>() {
                c.fast_queue = n.clamp(16, 4096);
            }
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_FAST_TIMEOUT_MS") {
            if let Ok(n) = v.parse::<u64>() {
                c.fast_timeout_ms = n.clamp(25, 500);
            }
        }
        c
    }
}

struct Job {
    evaluator: Arc<Evaluator>,
    req: NativeRequest,
    plan: InspectPlan,
    resp_tx: SyncSender<Option<NativeHit>>,
}

/// 全局 inspect 线程池（Engine 共用）。
pub struct InspectPool {
    fast_tx: SyncSender<Job>,
    deep_tx: SyncSender<Job>,
    fast_timeout: Duration,
}

static POOL: OnceLock<InspectPool> = OnceLock::new();

pub fn global() -> &'static InspectPool {
    POOL.get_or_init(|| InspectPool::new(InspectPoolConfig::from_env()))
}

impl InspectPool {
    pub fn new(cfg: InspectPoolConfig) -> Self {
        let fast_tx = spawn_pool("native-fast", cfg.fast_workers, cfg.fast_queue);
        let deep_tx = spawn_pool("native-deep", cfg.deep_workers, cfg.deep_queue);
        Self {
            fast_tx,
            deep_tx,
            fast_timeout: Duration::from_millis(cfg.fast_timeout_ms),
        }
    }

    /// 在对应路径池执行 inspect；队列满时同步 fallback。
    pub fn inspect_with_plan(
        &self,
        evaluator: Arc<Evaluator>,
        req: NativeRequest,
        plan: InspectPlan,
    ) -> Option<NativeHit> {
        let path = plan.path;
        let (resp_tx, resp_rx) = sync_channel(1);
        let job = Job {
            evaluator: evaluator.clone(),
            req: req.clone(),
            plan: plan.clone(),
            resp_tx,
        };
        let tx = match path {
            InspectPath::Fast => &self.fast_tx,
            InspectPath::Deep => &self.deep_tx,
        };
        if tx.try_send(job).is_err() {
            return evaluator.inspect(&req);
        }
        if path == InspectPath::Fast {
            match resp_rx.recv_timeout(self.fast_timeout) {
                Ok(hit) => hit,
                Err(_) => {
                    nerve_antibody_metrics::global().record_fast_pool_escalate();
                    if plan.inline_fast_lane {
                        // 内联快通道：同步完成 Fast，不升 Deep（1200ms 级）。
                        return evaluator.inspect_plan(&req, plan);
                    }
                    self.inspect_deep_on_timeout(evaluator, req, plan)
                }
            }
        } else {
            resp_rx.recv().ok().flatten()
        }
    }

    /// 兼容旧调用：内部仍会重复 plan（勿在热路径使用）。
    pub fn inspect(
        &self,
        evaluator: Arc<Evaluator>,
        req: NativeRequest,
        path: InspectPath,
    ) -> Option<NativeHit> {
        let plan = evaluator.plan_inspect(&req, PlanCacheHints::default());
        debug_assert_eq!(plan.path, path);
        self.inspect_with_plan(evaluator, req, plan)
    }

    /// Fast 池超时：投递 deep 池，避免高负载 FN。
    fn inspect_deep_on_timeout(
        &self,
        evaluator: Arc<Evaluator>,
        req: NativeRequest,
        mut plan: InspectPlan,
    ) -> Option<NativeHit> {
        plan.path = InspectPath::Deep;
        let (resp_tx, resp_rx) = sync_channel(1);
        let job = Job {
            evaluator: evaluator.clone(),
            req: req.clone(),
            plan,
            resp_tx,
        };
        if self.deep_tx.try_send(job).is_err() {
            return evaluator.inspect(&req);
        }
        resp_rx.recv().ok().flatten()
    }
}

fn spawn_pool(name: &str, workers: usize, queue: usize) -> SyncSender<Job> {
    let (tx, rx) = sync_channel::<Job>(queue);
    let rx = Arc::new(std::sync::Mutex::new(rx));
    for i in 0..workers {
        let rx = rx.clone();
        let tname = format!("{name}-{i}");
        thread::Builder::new()
            .name(tname)
            .spawn(move || {
                loop {
                    let job = {
                        let guard = rx.lock().expect("pool rx");
                        guard.recv()
                    };
                    let Ok(job) = job else { break };
                    let hit = job.evaluator.inspect_plan(&job.req, job.plan);
                    let _ = job.resp_tx.send(hit);
                }
            })
            .expect("spawn inspect worker");
    }
    tx
}
