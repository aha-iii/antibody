use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use nerve_antibody_metrics::InspectPath;
use nerve_antibody_runtime::PlanCacheHints;
use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    std::env::set_var("NERVE_NATIVE_DEV_PACK", "1");
    std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "auto");
    let pack = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/baseline");
    let eng = Engine::load_pack(&pack).unwrap();
    let ev = eng.evaluator_for(NativeLevel::Medium);
    let req = NativeRequest {
        method: "GET".into(),
        host: "example.com".into(),
        uri: "/api/item".into(),
        query: "q=1' OR 1=1--".into(),
        headers: HashMap::from([("User-Agent".into(), "nerve-sample/1.0".into())]),
        body: "".into(),
        ..Default::default()
    };
    // load real sample
    let text = std::fs::read_to_string(pack.join("samples/01-sqli/sqli-dual.yaml")).unwrap();
    println!("sample file head:\n{}", text.lines().take(25).collect::<Vec<_>>().join("\n"));
    let plan = ev.plan_inspect(&req, PlanCacheHints::default());
    println!(
        "probe path={} zone={:?} score={:.3} route_deep={} decode={} evasion={}",
        plan.path.as_str(),
        plan.ris_zone,
        plan.route_score,
        plan.route_deep,
        plan.decode_hint,
        plan.evasion_hint
    );
    let hit = eng.inspect(&req, NativeLevel::Medium).unwrap();
    println!("hit={:?}", hit.as_ref().map(|h| (&h.action, &h.rule_id)));
}
