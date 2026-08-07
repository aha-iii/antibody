//! 从 bench 报告 / 合成样本校准 route_gate 权重与 deep_threshold。
//!
//! ```bash
//! cargo run -p nerve-antibody-bench --bin nerve-antibody-calibrate-route --release -- \
//!   --input /tmp/bench-report.json \
//!   --out-weights packs/baseline/config/route_weights.json \
//!   --model stumps --print-threshold
//! ```

use nerve_antibody_runtime::{
    extract_features, parse_request_summary, route_sample, scan_threshold_curve, train_logistic,
    train_logistic_with_stumps, NativeRequest, RouteTrainSample,
};
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Deserialize)]
struct BenchReport {
    #[serde(default)]
    items: Vec<BenchItem>,
    #[serde(default)]
    results: Vec<BenchItem>,
    #[serde(default)]
    cases: Vec<BenchItem>,
}

#[derive(Debug, Deserialize, Clone)]
struct BenchItem {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    expect: String,
    #[serde(default)]
    request_summary: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    body: String,
}

fn items_from_report(r: BenchReport) -> Vec<BenchItem> {
    if !r.items.is_empty() {
        return r.items;
    }
    if !r.results.is_empty() {
        return r.results;
    }
    r.cases
}

fn is_attack(it: &BenchItem) -> bool {
    it.expect.eq_ignore_ascii_case("block")
        || it.kind.eq_ignore_ascii_case("black")
        || it.kind.eq_ignore_ascii_case("malicious")
}

fn req_from_item(it: &BenchItem) -> NativeRequest {
    if !it.request_summary.is_empty() {
        return parse_request_summary(&it.request_summary);
    }
    NativeRequest {
        method: if it.method.is_empty() {
            "GET".into()
        } else {
            it.method.clone()
        },
        uri: if it.uri.is_empty() {
            "/".into()
        } else {
            it.uri.clone()
        },
        query: it.query.clone(),
        body: it.body.clone(),
        ..Default::default()
    }
}

fn synthetic_clean() -> Vec<RouteTrainSample> {
    let cleans = [
        ("GET", "/api/users", "page=1&size=20", ""),
        ("GET", "/health", "", ""),
        ("GET", "/static/app.js", "v=1", ""),
        ("GET", "/favicon.ico", "", ""),
        ("POST", "/api/search", "", r#"{"q":"hello","page":1}"#),
        (
            "POST",
            "/open/api/msg/sms/v1/send",
            "",
            r#"{"tenantCode":"t","phoneNumber":"13800138000"}"#,
        ),
        ("GET", "/api/search", "q=hello-world&page=1", ""),
    ];
    cleans
        .into_iter()
        .map(|(m, u, q, b)| {
            let req = NativeRequest {
                method: m.into(),
                uri: u.into(),
                query: q.into(),
                body: b.into(),
                content_type: if b.starts_with('{') {
                    Some("application/json".into())
                } else {
                    None
                },
                ..Default::default()
            };
            let sample = route_sample(&req, 12 * 1024);
            RouteTrainSample {
                features: extract_features(&req, &sample),
                deep: false,
            }
        })
        .collect()
}

fn synthetic_attacks() -> Vec<RouteTrainSample> {
    let attacks = [
        ("GET", "/x", "id=1' union select null--", ""),
        ("GET", "/x", "id=1%27%20or%20%271%27%3D%271", ""),
        ("GET", "/x", "q=<script>alert(1)</script>", ""),
        ("GET", "/x", "f=../../etc/passwd", ""),
        ("POST", "/x", "", r#"{"q":"1; drop table t--"}"#),
    ];
    attacks
        .into_iter()
        .map(|(m, u, q, b)| {
            let req = NativeRequest {
                method: m.into(),
                uri: u.into(),
                query: q.into(),
                body: b.into(),
                content_type: if b.starts_with('{') {
                    Some("application/json".into())
                } else {
                    None
                },
                ..Default::default()
            };
            let sample = route_sample(&req, 12 * 1024);
            RouteTrainSample {
                features: extract_features(&req, &sample),
                deep: true,
            }
        })
        .collect()
}

fn main() -> ExitCode {
    let mut input: Option<PathBuf> = None;
    let mut out_weights = PathBuf::from("packs/baseline/config/route_weights.json");
    let mut out_curve: Option<PathBuf> = None;
    let mut epochs: usize = 80;
    let mut lr: f32 = 0.35;
    let mut max_miss: f64 = 0.01;
    let mut print_threshold = false;
    let mut use_stumps = false;
    let mut stump_rounds: usize = 8;
    let mut i = 1;
    let args: Vec<String> = env::args().collect();
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--out-weights" | "-o" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    out_weights = PathBuf::from(p);
                }
            }
            "--out-curve" => {
                i += 1;
                out_curve = args.get(i).map(PathBuf::from);
            }
            "--epochs" => {
                i += 1;
                epochs = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(epochs);
            }
            "--lr" => {
                i += 1;
                lr = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(lr);
            }
            "--max-miss" => {
                i += 1;
                max_miss = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(max_miss);
            }
            "--model" => {
                i += 1;
                if let Some(m) = args.get(i) {
                    use_stumps = m.eq_ignore_ascii_case("stumps")
                        || m.eq_ignore_ascii_case("logistic+stumps");
                }
            }
            "--stump-rounds" => {
                i += 1;
                stump_rounds = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(stump_rounds);
            }
            "--print-threshold" => print_threshold = true,
            "-h" | "--help" => {
                eprintln!(
                    "usage: nerve-antibody-calibrate-route [--input bench.json] [--out-weights path] [--out-curve path] [--model logistic|stumps] [--max-miss 0.01] [--print-threshold]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let mut samples: Vec<RouteTrainSample> = synthetic_clean();
    samples.extend(synthetic_attacks());
    if let Some(path) = &input {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("read {}: {e}", path.display());
                return ExitCode::from(1);
            }
        };
        let items = if let Ok(rep) = serde_json::from_str::<BenchReport>(&text) {
            items_from_report(rep)
        } else if let Ok(arr) = serde_json::from_str::<Vec<BenchItem>>(&text) {
            arr
        } else {
            eprintln!("cannot parse bench JSON");
            return ExitCode::from(1);
        };
        for it in items {
            let req = req_from_item(&it);
            let sample = route_sample(&req, 12 * 1024);
            samples.push(RouteTrainSample {
                features: extract_features(&req, &sample),
                deep: is_attack(&it),
            });
        }
    }

    let n_atk = samples.iter().filter(|s| s.deep).count();
    let n_clean = samples.len() - n_atk;
    eprintln!(
        "samples total={} attack={} clean={} model={}",
        samples.len(),
        n_atk,
        n_clean,
        if use_stumps {
            "logistic+stumps"
        } else {
            "logistic"
        }
    );

    let weights = if use_stumps {
        train_logistic_with_stumps(&samples, epochs, lr, stump_rounds)
    } else {
        train_logistic(&samples, epochs, lr)
    };

    let report = scan_threshold_curve(&samples, &weights, max_miss);
    let json = weights.to_json_pretty();
    if let Some(parent) = out_weights.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&out_weights, format!("{json}\n")) {
        eprintln!("write {}: {e}", out_weights.display());
        return ExitCode::from(1);
    }
    eprintln!("wrote {}", out_weights.display());

    if let Some(curve_path) = &out_curve {
        if let Ok(body) = serde_json::to_string_pretty(&report) {
            let _ = fs::write(curve_path, format!("{body}\n"));
            eprintln!("wrote curve {}", curve_path.display());
        }
    }

    eprintln!(
        "recommended deep_threshold={:.2} gray_threshold={:.2} attack_fast_miss={:.2}% clean_fast_ratio={:.2}%",
        report.recommended_deep_threshold,
        report.recommended_gray_threshold,
        report.attack_fast_miss * 100.0,
        report.clean_fast_ratio * 100.0
    );
    if print_threshold {
        println!("{:.2}", report.recommended_deep_threshold);
    }
    eprintln!("threshold_curve (thr, attack_miss%, clean_fast%):");
    for p in report.curve.iter().step_by(4) {
        eprintln!(
            "  {:.2}  miss={:.1}%  fast={:.1}%",
            p.threshold,
            p.attack_fast_miss * 100.0,
            p.clean_fast_ratio * 100.0
        );
    }
    ExitCode::SUCCESS
}
