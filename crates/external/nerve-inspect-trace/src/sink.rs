use std::cell::RefCell;
use std::sync::{Arc, Mutex};

/// Native expert engine stage timings (microseconds). Decoupled from `nerve-antibody-metrics`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeInspectStages {
    pub decode_us: u64,
    pub aho_us: u64,
    pub regex_us: u64,
    pub semantic_us: u64,
    pub fusion_us: u64,
}

thread_local! {
    static THREAD_SINK: RefCell<Option<Arc<Mutex<Vec<nerve_waf_core::InspectNodeTiming>>>>> =
        const { RefCell::new(None) };
}

thread_local! {
    static THREAD_PATH: RefCell<Option<Arc<Mutex<Option<String>>>>> = const { RefCell::new(None) };
}

pub fn set_thread_sink(sink: Option<Arc<Mutex<Vec<nerve_waf_core::InspectNodeTiming>>>>) {
    THREAD_SINK.with(|t| *t.borrow_mut() = sink);
}

pub fn set_thread_path(path: Option<Arc<Mutex<Option<String>>>>) {
    THREAD_PATH.with(|t| *t.borrow_mut() = path);
}

pub fn clear_thread_sink() {
    set_thread_sink(None);
    set_thread_path(None);
}

pub fn current_thread_sink() -> Option<Arc<Mutex<Vec<nerve_waf_core::InspectNodeTiming>>>> {
    THREAD_SINK.with(|t| t.borrow().clone())
}

pub fn current_thread_path() -> Option<Arc<Mutex<Option<String>>>> {
    THREAD_PATH.with(|t| t.borrow().clone())
}

/// True when a request-scoped sink is installed on this thread (forces sync inspect; no pool).
#[inline]
pub fn tracing_sink_active() -> bool {
    THREAD_SINK.with(|t| t.borrow().is_some())
}

fn push_thread(name: &'static str, us: u64) {
    THREAD_SINK.with(|t| {
        if let Some(sink) = t.borrow().as_ref() {
            if let Ok(mut nodes) = sink.lock() {
                nodes.push(nerve_waf_core::InspectNodeTiming {
                    n: name.into(),
                    us,
                    d: Default::default(),
                });
            }
        }
    });
}

pub fn record_native_stages(stages: &NativeInspectStages) {
    if !crate::trace_enabled() {
        return;
    }
    push_thread("native.decode", stages.decode_us);
    push_thread("native.aho", stages.aho_us);
    push_thread("native.regex", stages.regex_us);
    push_thread("native.semantic", stages.semantic_us);
    push_thread("native.fusion", stages.fusion_us);
}

pub fn record_native_plan(us: u64) {
    if !crate::trace_enabled() {
        return;
    }
    push_thread("native.plan", us);
}

pub fn record_native_path(path: &str) {
    if !crate::trace_enabled() {
        return;
    }
    THREAD_PATH.with(|t| {
        if let Some(slot) = t.borrow().as_ref() {
            if let Ok(mut p) = slot.lock() {
                *p = Some(path.into());
            }
        }
    });
}
