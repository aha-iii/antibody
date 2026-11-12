//! Offline samples regression against baseline pack.
//!
//! ```bash
//! cargo run -p nerve-antibody-bench --bin nerve-antibody-samples-regress --release
//! LEVEL=medium PACK=packs/baseline ...
//! ```

use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use nerve_antibody_metrics::InspectPath;
use nerve_antibody_runtime::PlanCacheHints;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct SampleFile {
    id: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    expect_action: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    min_level: String,
    request: SampleReq,
}

#[derive(Debug, Deserialize)]
struct SampleReq {
    #[serde(default = "default_get")]
    method: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    uri: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: String,
}

fn default_get() -> String {
    "GET".into()
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_yaml(&p, out);
            continue;
        }
        if p.extension()
            .and_then(|x| x.to_str())
            .map(|x| x == "yaml" || x == "yml")
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

fn resolve_pack() -> PathBuf {
    if let Ok(p) = env::var("NERVE_NATIVE_PACK").or_else(|_| env::var("PACK")) {
        return PathBuf::from(p);
    }
    let candidates = [
        PathBuf::from("packs/baseline"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs/baseline"),
    ];
    for c in candidates {
        if c.join("pack.toml").is_file() {
            return c;
        }
    }
    PathBuf::from("packs/baseline")
}

fn main() {
    let pack = resolve_pack();
    let level = NativeLevel::from_str(&env::var("LEVEL").unwrap_or_else(|_| "medium".into()))
        .unwrap_or(NativeLevel::Medium);
    let only_fail = env::var("ONLY_FAIL").ok().as_deref() == Some("1");
    let limit: Option<usize> = env::var("LIMIT").ok().and_then(|s| s.parse().ok());
    // 子串过滤路径 / rule_id / sample id（例：FILTER=gotestwaf）
    let filter = env::var("FILTER").unwrap_or_default().to_ascii_lowercase();

    eprintln!(
        "pack={} level={} filter={}",
        pack.display(),
        level.as_str(),
        if filter.is_empty() {
            "*"
        } else {
            filter.as_str()
        }
    );
    let eng = Engine::load_pack(&pack).unwrap_or_else(|e| {
        eprintln!("load pack failed: {e}");
        std::process::exit(2);
    });

    let samples_dir = pack.join("samples");
    let mut files = Vec::new();
    collect_yaml(&samples_dir, &mut files);
    files.sort();

    let mut total = 0usize;
    let mut ok = 0usize;
    let mut fail_pos = 0usize; // expect block/observe but got pass
    let mut fail_neg = 0usize; // expect pass but got block
    let mut errors = 0usize;
    let mut fail_rows: Vec<String> = Vec::new();
    let mut clean_total = 0usize;
    let mut clean_fast = 0usize;

    'files: for f in files {
        if !filter.is_empty() {
            let path_lc = f.to_string_lossy().to_ascii_lowercase();
            if !path_lc.contains(&filter) {
                continue;
            }
        }
        let text = match fs::read_to_string(&f) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("read {}: {e}", f.display());
                errors += 1;
                continue;
            }
        };
        let list: Vec<SampleFile> = match serde_yaml::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("yaml {}: {e}", f.display());
                errors += 1;
                continue;
            }
        };
        for s in list {
            if let Some(lim) = limit {
                if total >= lim {
                    break 'files;
                }
            }
            total += 1;
            let expect = s.expect_action.as_str();
            let req = NativeRequest {
                method: s.request.method,
                host: s.request.host,
                uri: s.request.uri,
                query: s.request.query,
                headers: s.request.headers,
                body: s.request.body,
                ..Default::default()
            };
            // 样本 / 规则可能要求 high；用 max(CLI level, sample.min_level) 保证规则在档。
            let case_level = {
                let sample_lv = NativeLevel::from_str(if s.min_level.is_empty() {
                    "low"
                } else {
                    &s.min_level
                })
                .unwrap_or(NativeLevel::Low);
                if sample_lv.rank() > level.rank() {
                    sample_lv
                } else {
                    level
                }
            };
            let evaluator = eng.evaluator_for(case_level);
            let plan = evaluator.plan_inspect(&req, PlanCacheHints::default());
            if expect == "pass" {
                clean_total += 1;
                if plan.path == InspectPath::Fast {
                    clean_fast += 1;
                } else if env::var("DUMP_DEEP").ok().as_deref() == Some("1") {
                    eprintln!(
                        "DEEP_PASS\tid={}\trule={}\tpath={}\tscore={:.3}\troute_deep={}\tdecode={}\tevasion={}\turi={}\tq={}",
                        s.id,
                        s.rule_id,
                        plan.path.as_str(),
                        plan.route_score,
                        plan.route_deep,
                        plan.decode_hint,
                        plan.evasion_hint,
                        req.uri,
                        req.query
                    );
                }
            }
            let hit = match eng.inspect(&req, case_level) {
                Ok(h) => h,
                Err(e) => {
                    errors += 1;
                    fail_rows.push(format!(
                        "ERR\t{}\t{}\t{}\tinspect:{e}",
                        s.category, s.rule_id, s.id
                    ));
                    continue;
                }
            };
            let actual = match &hit {
                Some(h) if h.action.eq_ignore_ascii_case("block") => "block",
                Some(h) if h.action.eq_ignore_ascii_case("challenge") => "challenge",
                Some(h) if h.action.eq_ignore_ascii_case("observe") => "observe",
                Some(h) if h.action.eq_ignore_ascii_case("allow") => "allow",
                Some(h) if h.action.is_empty() => "empty",
                Some(_) => "other",
                None => "pass",
            };
            // block 期望：拦截或 challenge（融合层强处置）均算正样本命中
            // pass 期望：不得 block/challenge
            let passed = match expect {
                "block" => matches!(actual, "block" | "challenge"),
                "observe" => matches!(actual, "observe" | "block" | "challenge"),
                "pass" => !matches!(actual, "block" | "challenge"),
                _ => !matches!(actual, "block" | "challenge"),
            };

            if passed {
                ok += 1;
                if !only_fail {
                    // keep quiet for success
                }
            } else {
                if expect == "block" || expect == "observe" {
                    fail_pos += 1;
                } else {
                    fail_neg += 1;
                }
                let rule_hit = hit
                    .as_ref()
                    .map(|h| h.rule_id.clone())
                    .unwrap_or_else(|| "-".into());
                fail_rows.push(format!(
                    "FAIL\texpect={expect}\tactual={actual}\thit_rule={rule_hit}\t{}\t{}\t{}",
                    s.category, s.rule_id, s.id
                ));
            }
        }
    }

    println!("TOTAL\t{total}");
    println!("OK\t{ok}");
    println!("FAIL_POS\t{fail_pos}"); // expected attack, not blocked
    println!("FAIL_NEG\t{fail_neg}"); // expected pass, blocked (FP)
    println!("ERRORS\t{errors}");
    let rate = if total == 0 {
        0.0
    } else {
        (ok as f64) * 100.0 / (total as f64)
    };
    println!("PASS_RATE\t{rate:.2}%");
    let clean_fast_ratio = if clean_total == 0 {
        0.0
    } else {
        (clean_fast as f64) * 100.0 / (clean_total as f64)
    };
    println!("CLEAN_TOTAL\t{clean_total}");
    println!("CLEAN_FAST\t{clean_fast}");
    println!("CLEAN_FAST_RATIO\t{clean_fast_ratio:.2}%");

    let report = pack.join("samples-regression-report.txt");
    let mut body = String::new();
    body.push_str(&format!(
        "pack={} level={} total={} ok={} fail_pos={} fail_neg={} errors={} pass_rate={:.2}% clean_fast_ratio={:.2}% ({}/{})\n\n",
        pack.display(),
        level.as_str(),
        total,
        ok,
        fail_pos,
        fail_neg,
        errors,
        rate,
        clean_fast_ratio,
        clean_fast,
        clean_total
    ));
    for row in &fail_rows {
        body.push_str(row);
        body.push('\n');
    }
    let _ = fs::write(&report, &body);
    eprintln!("report {}", report.display());

    // print first 40 failures
    for row in fail_rows.iter().take(40) {
        println!("{row}");
    }
    if fail_rows.len() > 40 {
        println!("... and {} more (see report)", fail_rows.len() - 40);
    }

    if fail_pos + fail_neg + errors > 0 {
        std::process::exit(1);
    }
}
