use nerve_waf_core::{InspectNodeTiming, InspectTimingReport};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct InspectTraceCtx {
    active: bool,
    t0: Instant,
    nodes: Arc<Mutex<Vec<InspectNodeTiming>>>,
    path: Arc<Mutex<Option<String>>>,
}

impl InspectTraceCtx {
    pub fn new() -> Self {
        let active = crate::trace_enabled();
        Self {
            active,
            t0: Instant::now(),
            nodes: Arc::new(Mutex::new(Vec::with_capacity(if active { 16 } else { 0 }))),
            path: Arc::new(Mutex::new(None)),
        }
    }

    #[inline]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn push(&mut self, name: &'static str, us: u64, detail: Option<HashMap<String, String>>) {
        if !self.active {
            return;
        }
        if let Ok(mut nodes) = self.nodes.lock() {
            nodes.push(InspectNodeTiming {
                n: name.into(),
                us,
                d: detail.unwrap_or_default(),
            });
        }
    }

    pub fn set_path(&mut self, path: &str) {
        if !self.active {
            return;
        }
        if let Ok(mut p) = self.path.lock() {
            *p = Some(path.into());
        }
    }

    pub fn sink(&self) -> Option<Arc<Mutex<Vec<InspectNodeTiming>>>> {
        if self.active {
            Some(Arc::clone(&self.nodes))
        } else {
            None
        }
    }

    pub fn path_slot(&self) -> Option<Arc<Mutex<Option<String>>>> {
        if self.active {
            Some(Arc::clone(&self.path))
        } else {
            None
        }
    }

    pub fn into_report(self, blocked: bool) -> Option<InspectTimingReport> {
        if !self.active {
            return None;
        }
        let nodes = self.nodes.lock().ok()?.clone();
        let path = self.path.lock().ok()?.clone();
        Some(InspectTimingReport {
            total_us: self.t0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            nodes,
            path,
            blocked: Some(blocked),
        })
    }
}

impl Default for InspectTraceCtx {
    fn default() -> Self {
        Self::new()
    }
}
