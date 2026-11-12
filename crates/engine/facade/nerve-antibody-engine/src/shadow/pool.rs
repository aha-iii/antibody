//! Shadow deep 有界 worker 池（替代无界 thread::spawn）。

use nerve_antibody_runtime::{Evaluator, InspectMode, NativeHit, NativeRequest};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread;

pub struct ShadowJob {
    pub evaluator: Arc<Evaluator>,
    pub req: NativeRequest,
    pub on_done: Box<dyn FnOnce(Option<NativeHit>) + Send>,
}

#[derive(Debug, Clone)]
pub struct ShadowPoolConfig {
    pub workers: usize,
    pub queue: usize,
}

impl Default for ShadowPoolConfig {
    fn default() -> Self {
        Self {
            workers: 2,
            queue: 128,
        }
    }
}

impl ShadowPoolConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("NERVE_NATIVE_SHADOW_WORKERS") {
            if let Ok(e) = v.parse::<usize>() {
                c.workers = e.clamp(1, 16);
            }
        }
        if let Ok(v) = std::env::var("NERVE_NATIVE_SHADOW_QUEUE") {
            if let Ok(e) = v.parse::<usize>() {
                c.queue = e.clamp(16, 4096);
            }
        }
        c
    }
}

pub struct ShadowPool {
    tx: SyncSender<ShadowJob>,
}

impl ShadowPool {
    pub fn new(cfg: ShadowPoolConfig) -> Self {
        let (tx, rx) = sync_channel::<ShadowJob>(cfg.queue);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        for i in 0..cfg.workers {
            let rx = rx.clone();
            thread::Builder::new()
                .name(format!("native-shadow-{i}"))
                .spawn(move || loop {
                    let job = {
                        let guard = rx.lock().expect("shadow rx");
                        guard.recv()
                    };
                    let Ok(job) = job else { break };
                    // 影子深检只对本次调用生效：用线程局部覆盖，不再改写进程级
                    // env。原实现 set_var/remove_var 在多 worker 并发时会互相覆盖，
                    // 并会把主检测线程的 inspect 模式污染成 deep。
                    let hit = InspectMode::with_override(InspectMode::Deep, || {
                        job.evaluator.inspect(&job.req)
                    });
                    (job.on_done)(hit);
                })
                .expect("spawn shadow worker");
        }
        Self { tx }
    }

    pub fn try_submit(&self, job: ShadowJob) -> bool {
        self.tx.try_send(job).is_ok()
    }
}
