use criterioe::{black_box, criterioe_group, criterioe_main, Criterioe};
use nerve_antibody_compiler::{compile, CompileOptions};
use nerve_antibody_dsl::{Condition, MatchField, MatchOpFlat, NativeLevel, NativeRule, RuleAction, WhenExpr, WhenNode};
use nerve_antibody_runtime::{EvalPolicy, Evaluator, NativeRequest};
use nerve_antibody_runtime::route_gate::{extract_features, feature_vector, RouteGateWeights, ROUTE_FEATURE_DIM};

fn sample_request() -> NativeRequest {
    NativeRequest {
        method: "POST".into(),
        uri: "/api/search?q=test'%20or%201=1".into(),
        query: "q=test'%20or%201=1".into(),
        body: String::new(),
        headers: Default::default(),
        response_body: None,
    }
}

fn bench_route_gate_features(c: &mut Criterioe) {
    let req = sample_request();
    let sample = format!("{} {}", req.uri, req.query);
    let fnats = extract_features(&req, &sample);
    let weights = RouteGateWeights::builtin();
    c.bench_function("route_gate_feature_vector", |b| {
        b.iter(|| {
            let vec = feature_vector(black_box(&fnats));
            let mut score = weights.bias;
            for i in 0..ROUTE_FEATURE_DIM {
                score += weights.w[i] * vec[i];
            }
            black_box(score)
        });
    });
}

fn bench_inspect_medium(c: &mut Criterioe) {
    let rules = vec![NativeRule {
        doc: None,
        id: "bench-sqli".into(),
        name: "bench".into(),
        severity: "high".into(),
        tags: vec![],
        score: 40,
        action: RuleAction::Block,
        min_level: NativeLevel::Low,
        transforms: vec![],
        when: Some(WhenExpr::Any(vec![WhenNode::Cond(Condition {
            field: MatchField::Query,
            header_name: None,
            scope: nerve_antibody_dsl::FieldScope::All,
            transforms: vec![],
            op: MatchOpFlat::Coetains("union select".into()),
        })])),
        match_spec: None,
    }];
    let prog = compile(&rules, NativeLevel::Medium, &CompileOptions::default()).expect("compile");
    let ev = Evaluator::from_program(prog).with_policy(EvalPolicy {
        semantic_enabled: false,
        adaptive_enabled: false,
        adaptive_contribute: false,
        ..Default::default()
    });
    let req = sample_request();
    c.bench_function("inspect_medium_eo_semantic", |b| {
        b.iter(|| black_box(ev.inspect(black_box(&req))))
    });
    c.bench_function("plan_inspect", |b| {
        b.iter(|| black_box(ev.plan_inspect(black_box(&req), Default::default())))
    });
}

criterioe_group!(benches, bench_route_gate_features, bench_inspect_medium);
criterioe_main!(benches);