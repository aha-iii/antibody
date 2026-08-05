//! Shadow deep 有界 worker 池（替代无界 thread::spawn）。

use nerve_antibody_runtime::{Evaluator, NativeHit, NativeRequest};
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
                .spawn(move || {
                    loop {
                        let job = {
                            let guard = rx.lock().expect("shadow rx");
                            guard.recv()
                        };
                        let Ok(job) = job else { break };
                        std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "deep");
                        let hit = job.evaluator.inspect(&job.req);
                        std::env::remove_var("NERVE_NATIVE_INSPECT_MODE");
                        (job.on_done)(hit);
                    }
                })
                .expect("spawn shadow worker");
        }
        Self { tx }
    }

    pub fn try_submit(&self, job: ShadowJob) -> bool {
        self.tx.try_send(job).is_ok()
    }
}
