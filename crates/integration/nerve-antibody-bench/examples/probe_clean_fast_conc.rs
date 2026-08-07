use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn main() {
    std::env::set_var("NERVE_NATIVE_DEV_PACK", "1");
    std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "auto");
    std::env::set_var("NERVE_NATIVE_INSPECT_POOL", "0");
    let pack = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/baseline");
    let eng = Arc::new(Engine::load_pack(&pack).expect("pack"));
    let req = Arc::new(NativeRequest {
        method: "GET".into(),
        host: "example.com".into(),
        uri: "/api/search".into(),
        query: "q=hello-world&page=1&id=550e8400-e29b-41d4-a716-446655440000".into(),
        headers: HashMap::from([("User-Agent".into(), "nerve-sample/1.0".into())]),
        body: "".into(),
        ..Default::default()
    });
    for _ in 0..3 {
        let _ = eng.inspect_exec(&req, NativeLevel::Medium);
    }
    let workers: usize = std::env::var("WORKERS").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    let per: usize = std::env::var("PER").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    let mut handles = Vec::new();
    let t0 = Instant::now();
    for _ in 0..workers {
        let eng = eng.clone();
        let req = req.clone();
        handles.push(thread::spawn(move || {
            let mut sum_fast = 0u64;
            let mut max_fast = 0u64;
            let mut n = 0u64;
            for _ in 0..per {
                let ex = eng.inspect_exec(&req, NativeLevel::Medium).expect("exec");
                sum_fast += ex.fast_us;
                max_fast = max_fast.max(ex.fast_us);
                n += 1;
            }
            (sum_fast, max_fast, n)
        }));
    }
    let mut sum = 0u64;
    let mut max = 0u64;
    let mut n = 0u64;
    for h in handles {
        let (s, m, c) = h.join().unwrap();
        sum += s;
        max = max.max(m);
        n += c;
    }
    let wall = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "workers={workers} per={per} n={n} avg_fast_ms={:.2} max_fast_ms={:.2} wall_ms={:.1} wall_per_case_ms={:.2}",
        (sum as f64 / n as f64) / 1000.0,
        max as f64 / 1000.0,
        wall,
        wall / n as f64,
    );
    let snap = nerve_antibody_metrics::global().snapshot();
    println!(
        "budget_exhausted={} inspect_fast={} stage_aho_us_avg={} stage_regex_us_avg={}",
        snap.budget_exhausted, snap.inspect_fast, snap.stage_aho_us_avg, snap.stage_regex_us_avg
    );
}
