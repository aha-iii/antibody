//! Per-request inspect node timing (env-gated; optional via callers' `inspect-trace` feature).

mod log;
mod scope;
mod sink;

pub use log::{emit_inspect_trace_log, InspectTraceMeta};
pub use scope::InspectTraceCtx;
pub use sink::{
    clear_thread_sink, current_thread_path, current_thread_sink, record_native_path,
    record_native_plan, record_native_stages, set_thread_path, set_thread_sink,
    tracing_sink_active, NativeInspectStages,
};

use nerve_waf_core::InspectTimingReport;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();

/// Read `NERVE_INSPECT_TRACE` once at process start.
pub fn init_from_env() {
    INIT.call_once(|| {
        let on = std::env::var("NERVE_INSPECT_TRACE")
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on")
            })
            .unwrap_or(false);
        ENABLED.store(on, Ordering::Relaxed);
    });
}

#[inline]
pub fn trace_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn min_us_threshold() -> u64 {
    static MIN: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        std::env::var("NERVE_INSPECT_TRACE_MIN_US")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    })
}

fn log_enabled() -> bool {
    std::env::var("NERVE_INSPECT_TRACE_LOG")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

pub fn finish_and_maybe_log(
    report: InspectTimingReport,
    meta: &InspectTraceMeta,
) -> InspectTimingReport {
    if report.total_us >= min_us_threshold() && log_enabled() {
        emit_inspect_trace_log(&report, meta);
    }
    report
}

/// Time `f`, then push `name` onto the ctx. Passes `&mut Option` so nested stages can reuse the same ctx.
pub fn maybe_trace<T>(
    ctx: &mut Option<&mut InspectTraceCtx>,
    name: &'static str,
    f: impl FnOnce(&mut Option<&mut InspectTraceCtx>) -> T,
) -> T {
    let active = ctx.as_ref().is_some_and(|c| c.is_active());
    if !active {
        return f(ctx);
    }
    let t0 = Instant::now();
    let out = f(ctx);
    let us = t0.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    if let Some(c) = ctx.as_deref_mut() {
        c.push(name, us, None);
    }
    out
}
