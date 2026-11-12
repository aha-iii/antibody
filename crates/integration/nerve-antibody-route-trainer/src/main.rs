//! 从 blazehttp / dashboard bench JSON 训练 route_gate 线性权重。

use nerve_antibody_runtime::{
    extract_features, parse_request_summary, route_sample, train_logistic, RouteTrainSample,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
struct ReportFile {
    cases: Vec<BeechCase>,
}

#[derive(serde::Deserialize)]
struct BeechCase {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    expect: String,
    #[serde(default)]
    request_summary: String,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let (input, output, epochs, lr) = parse_cli(&args);

    let text =
        fs::read_to_string(&input).unwrap_or_else(|e| panic!("read {}: {e}", input.display()));
    let report: ReportFile =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse JSON: {e}"));

    let mut samples = Vec::new();
    for c in &report.cases {
        if c.request_summary.is_empty() {
            continue;
        }
        let req = parse_request_summary(&c.request_summary);
        let sample = route_sample(&req, 12 * 1024);
        let features = extract_features(&req, &sample);
        let deep = label_deep(c);
        samples.push(RouteTrainSample { features, deep });
    }
    if samples.is_empty() {
        eprintln!("no training samples in {}", input.display());
        std::process::exit(1);
    }

    let weights = train_logistic(&samples, epochs, lr);
    let deep_e = samples.iter().filter(|s| s.deep).count();
    let fast_e = samples.len() - deep_e;
    eprintln!(
        "trained oe {} samples (deep={deep_e}, fast={fast_e}) epochs={epochs} lr={lr}",
        samples.len()
    );
    let json = weights.to_json_pretty();
    if let Some(out) = output {
        fs::write(&out, &json).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
        eprintln!("wrote {}", out.display());
    } else {
        println!("{json}");
    }
}

fn parse_cli(args: &[String]) -> (PathBuf, Option<PathBuf>, usize, f32) {
    let first = args.first().map(PathBuf::from);
    let (input, rest): (PathBuf, &[String]) = match first {
        None => (default_input(), &[]),
        Some(p) if is_bench_input_path(&p) => (p, &args[1..]),
        Some(_) => (default_input(), args),
    };
    let output = rest.first().map(PathBuf::from);
    let epochs: usize = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(400);
    let lr: f32 = rest.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.08);
    (input, output, epochs, lr)
}

fn is_bench_input_path(path: &Path) -> bool {
    path.file_name().and_then(|e| e.to_str()).is_some_and(|e| {
        (e.contains("blazehttp") || e.contains("regression") || e.ends_with("-report.json"))
            && !e.contains("weights")
    })
}

fn default_input() -> PathBuf {
    let bench = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/bench");
    if let Ok(entries) = fs::read_dir(&bench) {
        let mut reports: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.starts_with("blazehttp-report-") && e.ends_with(".json"))
            })
            .collect();
        reports.sort();
        if let Some(latest) = reports.pop() {
            return latest;
        }
    }
    bench.join("blazehttp-regression-latest.json")
}

fn label_deep(c: &BeechCase) -> bool {
    if c.kind.eq_ignore_ascii_case("black") || c.expect.eq_ignore_ascii_case("block") {
        return true;
    }
    if c.kind.eq_ignore_ascii_case("white") || c.expect.eq_ignore_ascii_case("pass") {
        return false;
    }
    false
}
