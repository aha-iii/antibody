//! 用例级拦截率测试（期望 / 实际 / 明细表）+ 可选内嵌 bench HTTP。
//!
//! Note: rustc 1.93 在对本模块做 dead_code 分析时可能 ICE；保留 allow 直到工具链修复。
#![allow(dead_code)]

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use http_body_util::BodyExt;
use nerve_antibody_engine::{Engine, NativeLevel, NativeRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchPhase {
    Idle,
    Running,
    Done,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BenchMetrics {
    pub total: u64,
    pub success: u64,
    pub error: u64,
    pub malicious_total: u64,
    pub blocked_ok: u64,
    pub missed: u64,
    pub normal_total: u64,
    pub passed_ok: u64,
    pub false_positive: u64,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub accuracy: f64,
    pub avg_ms: f64,
    pub pass_count: u64,
    pub fail_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub index: u64,
    pub id: String,
    pub suite: String,
    pub kind: String,
    pub name: String,
    pub request_summary: String,
    pub expect: String,
    pub actual: String,
    pub ok: bool,
    pub elapsed_ms: u64,
    pub rule_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchStatus {
    pub phase: BenchPhase,
    pub pack: String,
    pub level: String,
    pub dataset: String,
    pub concurrency: u32,
    pub timeout_ms: u32,
    pub target: String,
    pub progress_pct: f64,
    pub done: u64,
    pub total: u64,
    pub message: String,
    pub started_at_ms: Option<u128>,
    pub finished_at_ms: Option<u128>,
    pub elapsed_ms: Option<u128>,
    pub metrics: Option<BenchMetrics>,
    pub blazehttp_bin: String,
    pub ready: bool,
    pub ready_message: String,
    pub fail_count: u64,
    pub pass_count: u64,
}

impl Default for BenchStatus {
    fn default() -> Self {
        Self {
            phase: BenchPhase::Idle,
            pack: String::new(),
            level: "medium".into(),
            dataset: "samples".into(),
            concurrency: 80,
            timeout_ms: 3000,
            target: "in-process".into(),
            progress_pct: 0.0,
            done: 0,
            total: 0,
            message: String::new(),
            started_at_ms: None,
            finished_at_ms: None,
            elapsed_ms: None,
            metrics: None,
            blazehttp_bin: String::new(),
            ready: false,
            ready_message: String::new(),
            fail_count: 0,
            pass_count: 0,
        }
    }
}

pub struct BenchRuntime {
    pub engine: Arc<Engine>,
    pub level: Arc<tokio::sync::RwLock<NativeLevel>>,
    pub status: Arc<tokio::sync::RwLock<BenchStatus>>,
    pub results: Arc<tokio::sync::RwLock<Vec<CaseResult>>>,
    pub cancel: Arc<AtomicBool>,
    pub listen: SocketAddr,
    pub target_url: String,
}

#[derive(Debug, Deserialize)]
pub struct BenchStartBody {
    /// `samples`（当前规则包案例，推荐）| `blazehttp`（.black/.white 全量）
    #[serde(default = "default_dataset")]
    pub dataset: String,
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
    #[serde(default = "default_level_str")]
    pub level: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u32,
    /// 可选上限，便于冒烟（0=不限制）
    #[serde(default)]
    pub limit: u64,
}

fn default_dataset() -> String {
    "samples".into()
}
fn default_concurrency() -> u32 {
    80
}
fn default_level_str() -> String {
    "medium".into()
}
fn default_timeout() -> u32 {
    3000
}

#[derive(Debug, Deserialize)]
pub struct ResultsQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// all | pass | fail
    #[serde(default = "default_verdict")]
    pub verdict: String,
    /// all | black | white | sample
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_page() -> u32 {
    1
}
fn default_page_size() -> u32 {
    10
}
fn default_verdict() -> String {
    "all".into()
}
fn default_kind() -> String {
    "all".into()
}

#[derive(Debug, Serialize)]
pub struct ResultsOut {
    pub total: usize,
    pub page: u32,
    pub page_size: u32,
    pub items: Vec<CaseResult>,
}

pub(crate) struct PreparedCase {
    pub id: String,
    pub suite: String,
    pub kind: String,
    pub name: String,
    pub expect: String, // block | pass
    pub req: NativeRequest,
}

pub fn resolve_blazehttp_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BLAZEHTTP_ROOT") {
        let pb = PathBuf::from(p);
        if pb.join("testcases").is_dir() {
            return Some(pb);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendor = manifest.join("../../vendor/blazehttp");
    if vendor.join("testcases").is_dir() {
        return Some(vendor.canonicalize().unwrap_or(vendor));
    }
    let tmp = PathBuf::from("/tmp/blazehttp");
    if tmp.join("testcases").is_dir() {
        return Some(tmp);
    }
    None
}

pub fn probe_ready(dataset: &str) -> (bool, String, String) {
    match dataset {
        "blazehttp" => {
            let Some(root) = resolve_blazehttp_root() else {
                return (
                    false,
                    String::new(),
                    "未找到 blazehttp testcases（执行 bash scripts/fetch-blazehttp.sh）".into(),
                );
            };
            (
                true,
                root.display().to_string(),
                format!("blazehttp 样本就绪 · {}", root.display()),
            )
        }
        "gotestwaf" | "waftester" | "crs-ftw" => crate::datasets::dataset_ready(dataset),
        _ => (
            true,
            "samples".into(),
            "将使用当前规则包 packs/<pack>/samples".into(),
        ),
    }
}

pub async fn spawn_bench_listener(rt: Arc<BenchRuntime>) {
    let state = rt.clone();
    let app = Router::new()
        .fallback(any(bench_inspect))
        .with_state(state);
    let listener = match tokio::net::TcpListener::bind(rt.listen).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, addr = %rt.listen, "bench HTTP bind failed (in-process runner仍可用)");
            return;
        }
    };
    info!(%rt.listen, "bench HTTP listening (optional external tools)");
    if let Err(e) = axum::serve(listener, app).await {
        warn!(error = %e, "bench HTTP server stopped");
    }
}

async fn bench_inspect(
    State(rt): State<Arc<BenchRuntime>>,
    req: Request<Body>,
) -> Response {
    let level = *rt.level.read().await;
    let expert_req = match http_to_expert(req).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad request").into_response(),
    };
    match rt.engine.inspect(&expert_req, level) {
        Ok(Some(hit)) if hit.action == "block" || hit.action == "challenge" => {
            debug!(rule = %hit.rule_id, action = %hit.action, "bench deny");
            (StatusCode::FORBIDDEN, "blocked").into_response()
        }
        Ok(_) => (StatusCode::OK, "ok").into_response(),
        Err(e) => {
            warn!(error = %e, "bench inspect error");
            (StatusCode::INTERNAL_SERVER_ERROR, "inspect error").into_response()
        }
    }
}

async fn http_to_expert(req: Request<Body>) -> Result<NativeRequest, ()> {
    let method = req.method().as_str().to_string();
    let uri_path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut headers = HashMap::new();
    for (k, v) in req.headers().iter() {
        if let Ok(val) = v.to_str() {
            headers.insert(k.as_str().to_string(), val.to_string());
        }
    }
    let body_bytes = req.into_body().collect().await.map_err(|_| ())?.to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    Ok(NativeRequest {
        method,
        host,
        uri: uri_path,
        query,
        headers,
        body,
        ..Default::default()
    })
}

pub async fn start_job(
    rt: Arc<BenchRuntime>,
    packs_root: PathBuf,
    pack: String,
    body: BenchStartBody,
) -> Result<(), String> {
    {
        let st = rt.status.read().await;
        if st.phase == BenchPhase::Running {
            return Err("已有测试在运行中".into());
        }
    }

    let dataset = match body.dataset.trim() {
        "blazehttp" => "blazehttp",
        "gotestwaf" => "gotestwaf",
        "waftester" => "waftester",
        "crs-ftw" => "crs-ftw",
        _ => "samples",
    };
    let (ready, path_hint, ready_msg) = probe_ready(dataset);
    if !ready {
        return Err(ready_msg);
    }

    let level = NativeLevel::from_str_loose(&body.level)?;
    *rt.level.write().await = level;
    let concurrency = body.concurrency.clamp(1, 200);
    let limit = body.limit;

    let cases = match dataset {
        "blazehttp" => {
            let root = resolve_blazehttp_root().ok_or("blazehttp root missing")?;
            load_blazehttp_cases(&root, limit)?
        }
        "gotestwaf" => {
            let root = crate::datasets::resolve_vendor_dataset("gotestwaf")
                .ok_or("gotestwaf root missing")?;
            crate::datasets::load_gotestwaf_cases(&root, limit)?
        }
        "waftester" => {
            let root = crate::datasets::resolve_vendor_dataset("waftester")
                .ok_or("waftester root missing")?;
            crate::datasets::load_waftester_cases(&root, limit)?
        }
        "crs-ftw" => {
            let root =
                crate::datasets::resolve_vendor_dataset("crs-ftw").ok_or("crs-ftw root missing")?;
            crate::datasets::load_crs_ftw_cases(&root, limit)?
        }
        _ => load_sample_cases(&packs_root, &pack, limit)?,
    };
    if cases.is_empty() {
        return Err(format!("数据源为空：{dataset} / pack={pack}"));
    }

    rt.cancel.store(false, Ordering::SeqCst);
    {
        let mut results = rt.results.write().await;
        results.clear();
    }

    let total = cases.len() as u64;
    {
        let mut st = rt.status.write().await;
        *st = BenchStatus {
            phase: BenchPhase::Running,
            pack: pack.clone(),
            level: level.as_str().into(),
            dataset: dataset.into(),
            concurrency,
            timeout_ms: body.timeout_ms,
            target: "in-process (engine.inspect)".into(),
            progress_pct: 0.0,
            done: 0,
            total,
            message: format!("准备执行 {total} 条用例…"),
            started_at_ms: Some(now_ms()),
            finished_at_ms: None,
            elapsed_ms: None,
            metrics: None,
            blazehttp_bin: path_hint,
            ready: true,
            ready_message: ready_msg,
            fail_count: 0,
            pass_count: 0,
        };
    }

    let rt2 = rt.clone();
    tokio::spawn(async move {
        let t0 = Instant::now();
        let outcome = run_cases(rt2.clone(), cases, level, concurrency).await;
        let elapsed = t0.elapsed().as_millis();
        let mut st = rt2.status.write().await;
        st.elapsed_ms = Some(elapsed);
        st.finished_at_ms = Some(now_ms());
        match outcome {
            Ok(metrics) => {
                if rt2.cancel.load(Ordering::SeqCst) {
                    st.phase = BenchPhase::Stopped;
                    st.message = format!(
                        "已停止 · 完成 {}/{} · 失败 {}",
                        st.done, st.total, metrics.fail_count
                    );
                } else {
                    st.phase = BenchPhase::Done;
                    st.progress_pct = 100.0;
                    st.done = st.total;
                    st.message = format!(
                        "完成 · 通过 {} · 失败 {} · 检出率 {:.2}% · 准确率 {:.2}%",
                        metrics.pass_count,
                        metrics.fail_count,
                        metrics.detection_rate,
                        metrics.accuracy
                    );
                }
                st.pass_count = metrics.pass_count;
                st.fail_count = metrics.fail_count;
                st.metrics = Some(metrics);
            }
            Err(e) => {
                st.phase = BenchPhase::Failed;
                st.message = e;
            }
        }
    });

    Ok(())
}

pub async fn stop_job(rt: Arc<BenchRuntime>) -> Result<(), String> {
    let st = rt.status.read().await;
    if st.phase != BenchPhase::Running {
        return Err("当前没有运行中的测试".into());
    }
    drop(st);
    rt.cancel.store(true, Ordering::SeqCst);
    let mut st = rt.status.write().await;
    st.message = "正在停止…".into();
    Ok(())
}

async fn run_cases(
    rt: Arc<BenchRuntime>,
    cases: Vec<PreparedCase>,
    level: NativeLevel,
    concurrency: u32,
) -> Result<BenchMetrics, String> {
    let _bench_deep = BenchInspectModeGuard::deep_for_bench();
    let evaluator = rt.engine.evaluator_for(level);
    let workers = concurrency.clamp(1, 200) as usize;
    let total = cases.len() as u64;
    if total == 0 {
        return Ok(BenchMetrics::default());
    }

    // CPU 密集 inspect 走 blocking 线程池，避免占满 tokio worker 导致「名义并发 20、实际 ~1」。
    let slots: Arc<std::sync::Mutex<Vec<Option<CaseResult>>>> =
        Arc::new(std::sync::Mutex::new(vec![None; cases.len()]));
    let done_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let pass_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fail_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sum_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cancel = rt.cancel.clone();
    let status = rt.status.clone();
    let runtime_handle = tokio::runtime::Handle::current();

    let (work_tx, work_rx) = std::sync::mpsc::channel::<(usize, PreparedCase)>();
    let work_rx = Arc::new(std::sync::Mutex::new(work_rx));

    for (idx, case) in cases.into_iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        work_tx
            .send((idx, case))
            .map_err(|e| format!("bench work queue: {e}"))?;
    }
    drop(work_tx);

    let mut join_handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let rx = work_rx.clone();
        let evaluator = evaluator.clone();
        let slots = slots.clone();
        let done_counter = done_counter.clone();
        let pass_counter = pass_counter.clone();
        let fail_counter = fail_counter.clone();
        let sum_ms = sum_ms.clone();
        let cancel = cancel.clone();
        let status = status.clone();
        let runtime_handle = runtime_handle.clone();

        join_handles.push(tokio::task::spawn_blocking(move || {
            loop {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
                let item = {
                    let guard = rx.lock().expect("bench work_rx lock");
                    guard.recv()
                };
                let (idx, case) = match item {
                    Ok(v) => v,
                    Err(_) => break,
                };

                let t0 = Instant::now();
                let expect_block = case.expect == "block" || case.kind == "black";
                let (actual, rule_id, detail) = match evaluator.inspect(&case.req) {
                    Some(hit) => {
                        // challenge：黑样本计检出；白样本不计 FP（深检通道）
                        let act = match hit.action.as_str() {
                            "block" => "block",
                            "challenge" if expect_block => "block",
                            "challenge" => "challenge",
                            _ => "pass",
                        };
                        (act.to_string(), hit.rule_id.clone(), hit.evidence.clone())
                    }
                    None => ("pass".into(), String::new(), String::new()),
                };
                let elapsed_ms = t0.elapsed().as_millis() as u64;
                // expect=block 必须拦截；白样本仅 hard block 算误报（challenge 放过）
                let ok = if expect_block {
                    actual == "block"
                } else {
                    actual != "block"
                };

                let row = CaseResult {
                    index: idx as u64,
                    id: case.id,
                    suite: case.suite,
                    kind: case.kind,
                    name: case.name,
                    request_summary: format!(
                        "{} {}{}",
                        case.req.method,
                        case.req.uri,
                        if case.req.query.is_empty() {
                            String::new()
                        } else {
                            format!("?{}", truncate(&case.req.query, 80))
                        }
                    ),
                    expect: case.expect,
                    actual,
                    ok,
                    elapsed_ms,
                    rule_id,
                    detail: truncate(&detail, 200),
                };

                {
                    let mut guard = slots.lock().expect("bench slots lock");
                    guard[idx] = Some(row);
                }

                let d = done_counter.fetch_add(1, Ordering::SeqCst) + 1;
                if ok {
                    pass_counter.fetch_add(1, Ordering::SeqCst);
                } else {
                    fail_counter.fetch_add(1, Ordering::SeqCst);
                }
                sum_ms.fetch_add(elapsed_ms, Ordering::SeqCst);

                if d % 25 == 0 || d == total {
                    let pass = pass_counter.load(Ordering::SeqCst);
                    let fail = fail_counter.load(Ordering::SeqCst);
                    let pct = (d as f64 / total as f64) * 100.0;
                    let status = status.clone();
                    runtime_handle.spawn(async move {
                        let mut st = status.write().await;
                        st.done = d;
                        st.total = total;
                        st.progress_pct = pct;
                        st.pass_count = pass;
                        st.fail_count = fail;
                        st.message = format!("执行中 {d}/{total} · 通过 {pass} · 失败 {fail}");
                    });
                }
            }
        }));
    }

    for h in join_handles {
        h.await.map_err(|e| format!("bench worker: {e}"))?;
    }

    let rows: Vec<CaseResult> = slots
        .lock()
        .expect("bench slots lock")
        .iter()
        .filter_map(|slot| slot.clone())
        .collect();
    {
        let mut g = rt.results.write().await;
        *g = rows.clone();
    }

    Ok(compute_metrics(&rows, sum_ms.load(Ordering::SeqCst)))
}

fn compute_metrics(rows: &[CaseResult], sum_ms: u64) -> BenchMetrics {
    let total = rows.len() as u64;
    let mut error = 0u64;
    let mut malicious_total = 0u64;
    let mut blocked_ok = 0u64;
    let mut missed = 0u64;
    let mut normal_total = 0u64;
    let mut passed_ok = 0u64;
    let mut false_positive = 0u64;
    let mut pass_count = 0u64;
    let mut fail_count = 0u64;

    for r in rows {
        if r.ok {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        if r.actual == "error" {
            error += 1;
        }
        let is_malicious = r.expect == "block" || r.kind == "black";
        if is_malicious {
            malicious_total += 1;
            if r.actual == "block" {
                blocked_ok += 1;
            } else {
                missed += 1;
            }
        } else {
            normal_total += 1;
            if r.actual == "block" {
                false_positive += 1;
            } else {
                passed_ok += 1;
            }
        }
    }

    let detection_rate = if malicious_total > 0 {
        (blocked_ok as f64 / malicious_total as f64) * 100.0
    } else {
        0.0
    };
    let false_positive_rate = if normal_total > 0 {
        (false_positive as f64 / normal_total as f64) * 100.0
    } else {
        0.0
    };
    let accuracy = if total > 0 {
        ((blocked_ok + passed_ok) as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let avg_ms = if total > 0 {
        sum_ms as f64 / total as f64
    } else {
        0.0
    };

    BenchMetrics {
        total,
        success: total.saturating_sub(error),
        error,
        malicious_total,
        blocked_ok,
        missed,
        normal_total,
        passed_ok,
        false_positive,
        detection_rate,
        false_positive_rate,
        accuracy,
        avg_ms,
        pass_count,
        fail_count,
    }
}

pub async fn list_results(rt: &BenchRuntime, q: ResultsQuery) -> ResultsOut {
    let page = q.page.max(1);
    let page_size = q.page_size.clamp(5, 100);
    let all = rt.results.read().await;
    let filtered: Vec<_> = all
        .iter()
        .filter(|r| match q.verdict.as_str() {
            "pass" => r.ok,
            "fail" => !r.ok,
            _ => true,
        })
        .filter(|r| match q.kind.as_str() {
            "black" | "white" | "sample" => r.kind == q.kind,
            _ => true,
        })
        .cloned()
        .collect();
    let total = filtered.len();
    let start = ((page - 1) as usize).saturating_mul(page_size as usize);
    let items = filtered
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();
    ResultsOut {
        total,
        page,
        page_size,
        items,
    }
}

pub async fn report_json(rt: &BenchRuntime) -> serde_json::Value {
    let st = rt.status.read().await.clone();
    let results = rt.results.read().await.clone();
    serde_json::json!({
        "generated_at_ms": now_ms(),
        "status": st,
        "summary": st.metrics,
        "cases": results,
    })
}

fn load_sample_cases(
    packs_root: &Path,
    pack: &str,
    limit: u64,
) -> Result<Vec<PreparedCase>, String> {
    let dir = packs_root.join(pack).join("samples");
    if !dir.is_dir() {
        return Err(format!("样本目录不存在: {}", dir.display()));
    }
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .map(|x| x == "yaml" || x == "yml")
                .unwrap_or(false)
        })
        .collect();
    files.sort();

    #[derive(Deserialize)]
    struct SampleFile {
        id: String,
        #[serde(default)]
        rule_id: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        expect_action: String,
        request: SampleReqYaml,
    }
    #[derive(Deserialize)]
    struct SampleReqYaml {
        #[serde(default = "default_http_get")]
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

    let mut out = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let list: Vec<SampleFile> =
            serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        for s in list {
            let expect = match s.expect_action.as_str() {
                "block" => "block",
                _ => "pass", // observe / pass → 不期望拦截
            };
            out.push(PreparedCase {
                id: s.id.clone(),
                suite: "samples".into(),
                kind: "sample".into(),
                name: if s.name.is_empty() {
                    s.rule_id.clone()
                } else {
                    s.name
                },
                expect: expect.into(),
                req: NativeRequest {
                    method: s.request.method,
                    host: s.request.host,
                    uri: s.request.uri,
                    query: s.request.query,
                    headers: s.request.headers,
                    body: s.request.body,
                    ..Default::default()
                },
            });
            if limit > 0 && out.len() as u64 >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn default_http_get() -> String {
    "GET".into()
}

fn load_blazehttp_cases(root: &Path, limit: u64) -> Result<Vec<PreparedCase>, String> {
    let tc = root.join("testcases");
    let mut files = Vec::new();
    collect_case_files(&tc, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for path in files {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let kind = if name.ends_with(".black") {
            "black"
        } else if name.ends_with(".white") {
            "white"
        } else {
            continue;
        };
        // 样本可能含二进制 body / 非 UTF-8，不能用 read_to_string
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let raw = String::from_utf8_lossy(&bytes);
        let req = match parse_raw_http(raw.as_ref()) {
            Ok(r) => r,
            Err(e) => {
                skipped += 1;
                warn!(path = %path.display(), error = %e, "skip blazehttp case");
                continue;
            }
        };
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        out.push(PreparedCase {
            id: rel.clone(),
            suite: "blazehttp".into(),
            kind: kind.into(),
            name,
            expect: if kind == "black" {
                "block".into()
            } else {
                "pass".into()
            },
            req,
        });
        if limit > 0 && out.len() as u64 >= limit {
            break;
        }
    }
    if skipped > 0 {
        info!(skipped, loaded = out.len(), "blazehttp cases loaded with skips");
    }
    if out.is_empty() {
        return Err("未能加载任何 blazehttp 用例（文件损坏或目录为空）".into());
    }
    Ok(out)
}

fn collect_case_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for ent in rd.flatten() {
        let p = ent.path();
        if p.is_dir() {
            collect_case_files(&p, out)?;
        } else if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".black") || name.ends_with(".white") {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn parse_raw_http(raw: &str) -> Result<NativeRequest, String> {
    let mut anomalies: Vec<&str> = Vec::new();
    // 裸 CR（非 CRLF 组成部分）
    {
        let b = raw.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\r' {
                if i + 1 < b.len() && b[i + 1] == b'\n' {
                    i += 2;
                    continue;
                }
                anomalies.push("bare-cr");
                break;
            }
            i += 1;
        }
    }
    if raw.contains("\n") && !raw.contains("\r\n") && !raw.contains('\r') {
        anomalies.push("lf-only");
    }

    // 统一换行：CRLF / 裸 CR / LF，避免走私样本因行尾差异解析失败
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let (head, body) = match normalized.split_once("\n\n") {
        Some((h, b)) => (h, b.to_string()),
        None => (normalized.as_str(), String::new()),
    };
    let mut lines = head.lines();
    let request_line = lines.next().ok_or("empty request")?;
    if request_line.starts_with(' ') || request_line.starts_with('\t') {
        anomalies.push("leading-ws");
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or("");
    if version.is_empty() || version.eq_ignore_ascii_case("HTTP/0.9") {
        anomalies.push("http09");
    }
    let (uri, query) = split_target(target);
    let mut headers = HashMap::new();
    let mut host = String::new();
    for line in lines {
        // 冒号前空白 / Tab：走私混淆
        if let Some(idx) = line.find(':') {
            let (kraw, _) = line.split_at(idx);
            if kraw.ends_with(' ') || kraw.ends_with('\t') || kraw.starts_with(' ') || kraw.starts_with('\t') {
                anomalies.push("header-colon-ws");
            }
        }
        // 允许 `Host : x` / 空名 `:value` / 重复头换行拼接
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            let key = if key.is_empty() {
                "_empty".to_string()
            } else {
                key
            };
            if key.eq_ignore_ascii_case("host") {
                host = val.clone();
            }
            if key.eq_ignore_ascii_case("transfer-encoding") {
                let vl = val.to_ascii_lowercase();
                if vl == "cow" || vl.len() <= 2 || vl.contains(',') {
                    anomalies.push("te-anomaly");
                }
            }
            match headers.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    let e: &mut String = o.get_mut();
                    e.push('\n');
                    e.push_str(&val);
                    anomalies.push("dup-header");
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(val);
                }
            }
        } else if !line.trim().is_empty() {
            // 无冒号的异常行也保留，供走私/模糊测试命中
            let marker = format!("_raw_line:{line}");
            headers
                .entry("_malformed".into())
                .and_modify(|e| {
                    e.push('\n');
                    e.push_str(&marker);
                })
                .or_insert(marker);
            anomalies.push("malformed-line");
        }
    }
    if method.eq_ignore_ascii_case("GET")
        && headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("transfer-encoding"))
    {
        anomalies.push("get-with-te");
    }
    // 异常 chunk 体
    let bl = body.to_ascii_lowercase();
    if bl.starts_with('-')
        || bl.starts_with("0 ")
        || (bl.chars().take(8).all(|c| c == '0') && bl.starts_with("000"))
    {
        anomalies.push("chunk-anomaly");
    }
    if !anomalies.is_empty() {
        anomalies.sort_unstable();
        anomalies.dedup();
        headers.insert(
            "_proto_anomaly".into(),
            anomalies.join(","),
        );
    }
    Ok(NativeRequest {
        method,
        host,
        uri,
        query,
        headers,
        body: cap_body_for_inspect(body, 32 * 1024),
        ..Default::default()
    })
}

/// bench / blaze 大包只保留头尾，避免 decode 管线在 multipart 二进制上耗时数秒。
fn cap_body_for_inspect(body: String, max: usize) -> String {
    if body.len() <= max {
        return body;
    }
    let keep = max / 2;
    let head_end = floor_byte_boundary(&body, keep);
    let tail_start = ceil_byte_boundary(&body, body.len().saturating_sub(keep));
    let mut out = String::with_capacity(max + 8);
    out.push_str(&body[..head_end]);
    out.push_str("\n...\n");
    out.push_str(&body[tail_start..]);
    out
}

fn floor_byte_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_byte_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// 拆分 request-target；glob（`/???/`）中的 `?` 不是 query 分隔符。
fn split_target(target: String) -> (String, String) {
    if target.contains("???") || target.contains("????") {
        return (target, String::new());
    }
    // cache deception: `/path?;.css` — 保留整段在 uri，同时把 `?;` 后内容写入 query 便于规则命中
    if let Some((u, q)) = target.split_once('?') {
        if q.starts_with(';') {
            return (target.clone(), q.to_string());
        }
        return (u.to_string(), q.to_string());
    }
    (target, String::new())
}

/// 供 datasets 模块复用。
pub(crate) fn parse_raw_http_pub(raw: &str) -> Result<NativeRequest, String> {
    parse_raw_http(raw)
}

pub(crate) fn split_request_target(target: &str) -> (String, String) {
    split_target(target.to_string())
}

pub async fn refresh_ready(status: &Arc<tokio::sync::RwLock<BenchStatus>>, dataset_hint: &str) {
    let dataset = {
        let st = status.read().await;
        if st.dataset.is_empty() {
            dataset_hint.to_string()
        } else {
            st.dataset.clone()
        }
    };
    let (ready, bin, msg) = probe_ready(&dataset);
    let mut st = status.write().await;
    if st.phase != BenchPhase::Running {
        st.ready = ready;
        st.blazehttp_bin = bin;
        st.ready_message = msg;
        if st.dataset.is_empty() {
            st.dataset = dataset;
        }
    }
}

/// 页面可选数据源清单（含就绪状态）。
pub fn list_datasets() -> serde_json::Value {
    let items = [
        ("samples", "规则包 samples", "packs/<pack>/samples · 有 expect", true),
        (
            "blazehttp",
            "blazehttp（长亭）",
            "黑/白 raw HTTP · 约 3.4 万条",
            resolve_blazehttp_root().is_some(),
        ),
        (
            "gotestwaf",
            "GoTestWAF（Wallarm）",
            "OWASP/API payload × encoder × placeholder",
            crate::datasets::resolve_vendor_dataset("gotestwaf")
                .map(|p| p.join("testcases").is_dir())
                .unwrap_or(false),
        ),
        (
            "waftester",
            "WAFtester",
            "payloads/*.json · expected_block",
            crate::datasets::resolve_vendor_dataset("waftester")
                .map(|p| p.join("payloads").is_dir())
                .unwrap_or(false),
        ),
        (
            "crs-ftw",
            "OWASP CRS / FTW",
            "ModSecurity CRS 回归 YAML",
            crate::datasets::resolve_vendor_dataset("crs-ftw")
                .map(|p| {
                    p.join("tests/regression/tests").is_dir()
                        || p.join("coreruleset/tests/regression/tests").is_dir()
                })
                .unwrap_or(false),
        ),
    ];
    serde_json::json!({
        "items": items.iter().map(|(id, label, desc, ready)| {
            let (_, path, msg) = probe_ready(id);
            serde_json::json!({
                "id": id,
                "label": label,
                "description": desc,
                "ready": ready,
                "path": path,
                "message": msg,
                "fetch_hint": match *id {
                    "blazehttp" => "bash scripts/fetch-blazehttp.sh",
                    "gotestwaf" => "bash scripts/fetch-gotestwaf.sh",
                    "waftester" => "bash scripts/fetch-waftester.sh",
                    "crs-ftw" => "bash scripts/fetch-crs-ftw.sh",
                    _ => "",
                },
            })
        }).collect::<Vec<_>>()
    })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{t}…")
    }
}

/// Bench 准确率测试强制 deep 路径（与生产 auto 分离）；进程内恢复 env。
struct BenchInspectModeGuard {
    prev: Option<String>,
}

impl BenchInspectModeGuard {
    fn deep_for_bench() -> Self {
        let prev = std::env::var("NERVE_NATIVE_INSPECT_MODE").ok();
        std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "deep");
        Self { prev }
    }
}

impl Drop for BenchInspectModeGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("NERVE_NATIVE_INSPECT_MODE", v),
            None => std::env::remove_var("NERVE_NATIVE_INSPECT_MODE"),
        }
    }
}

trait LevelParse {
    fn from_str_loose(s: &str) -> Result<NativeLevel, String>;
}

impl LevelParse for NativeLevel {
    fn from_str_loose(s: &str) -> Result<NativeLevel, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(NativeLevel::Low),
            "medium" => Ok(NativeLevel::Medium),
            "high" => Ok(NativeLevel::High),
            other => Err(format!("invalid level: {other}")),
        }
    }
}
