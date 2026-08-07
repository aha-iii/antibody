use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use nerve_antibody_runtime::PlanCacheHints;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    std::env::set_var("NERVE_NATIVE_DEV_PACK", "1");
    std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "auto");
    // disable pool for stable timing
    std::env::set_var("NERVE_NATIVE_INSPECT_POOL", "0");
    let pack = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/baseline");
    let eng = Engine::load_pack(&pack).expect("pack");
    let ev = eng.evaluator_for(NativeLevel::Medium);
    let req = NativeRequest {
        method: "GET".into(),
        host: "example.com".into(),
        uri: "/api/search".into(),
        query: "q=hello-world&page=1&id=550e8400-e29b-41d4-a716-446655440000".into(),
        headers: HashMap::from([("User-Agent".into(), "nerve-sample/1.0".into())]),
        body: "".into(),
        ..Default::default()
    };
    // warmup
    for _ in 0..5 {
        let _ = eng.inspect_exec(&req, NativeLevel::Medium);
    }
    let plan = ev.plan_inspect(&req, PlanCacheHints::default());
    println!(
        "plan path={} zone={} score={:.3} api_pos={} inline={} structure_hints route_deep={}",
        plan.path.as_str(),
        plan.ris_zone.as_str(),
        plan.route_score,
        plan.api_positive_lane,
        plan.inline_fast_lane,
        plan.route_deep,
    );
    let mut sum_ris = 0u64;
    let mut sum_fast = 0u64;
    let mut sum_deep = 0u64;
    let n = 30usize;
    let wall0 = Instant::now();
    for _ in 0..n {
        let ex = eng.inspect_exec(&req, NativeLevel::Medium).expect("exec");
        sum_ris += ex.ris_us;
        sum_fast += ex.fast_us;
        sum_deep += ex.deep_us;
    }
    let wall = wall0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "n={n} avg_ris_ms={:.3} avg_fast_ms={:.3} avg_deep_ms={:.3} wall_ms_total={:.1} wall_per_case_ms={:.2}",
        (sum_ris as f64 / n as f64) / 1000.0,
        (sum_fast as f64 / n as f64) / 1000.0,
        (sum_deep as f64 / n as f64) / 1000.0,
        wall,
        wall / n as f64,
    );
    let snap = nerve_antibody_metrics::global().snapshot();
    println!(
        "metrics inspect_fast={} inspect_deep={} budget_exhausted={} stage_aho_us_avg={} stage_regex_us_avg={} stage_decode_us_avg={}",
        snap.inspect_fast,
        snap.inspect_deep,
        snap.budget_exhausted,
        snap.stage_aho_us_avg,
        snap.stage_regex_us_avg,
        snap.stage_decode_us_avg,
    );
}
