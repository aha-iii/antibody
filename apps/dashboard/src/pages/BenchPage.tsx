import { useCallback, useEffect, useMemo, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NervePageHeader,
  NervePagination,
  NerveSelect,
  NerveTable,
  NerveTableToolbar,
  NerveTag,
  defaultPaginationState,
  type NervePaginationState,
  type NerveTableColumn,
  type NerveTagTone,
} from "@nerve/ui";
import {
  api,
  type BenchDatasetInfo,
  type BenchDatasetId,
  type BenchStatus,
  type CaseResult,
  type NativeLevel,
  type MetricsSnapshot,
  type Health,
} from "../api";

type Props = {
  health: Health | null;
};

type Row = CaseResult & Record<string, unknown>;

function fmtPct(n: number | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${n.toFixed(2)}%`;
}

function fmtNum(n: number | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return n.toLocaleString("zh-CN");
}

function phaseTone(phase: BenchStatus["phase"]): NerveTagTone {
  switch (phase) {
    case "running":
      return "blue";
    case "done":
      return "green";
    case "failed":
      return "red";
    case "stopped":
      return "orange";
    default:
      return "default";
  }
}

function phaseLabel(phase: BenchStatus["phase"]): string {
  switch (phase) {
    case "idle":
      return "待测";
    case "running":
      return "测试中";
    case "done":
      return "已完成";
    case "failed":
      return "失败";
    case "stopped":
      return "已停止";
    default:
      return phase;
  }
}

function Donut({
  value,
  color,
  label,
  sub,
}: {
  value: number;
  color: string;
  label: string;
  sub: string;
}) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, value));
  const dash = (pct / 100) * c;
  return (
    <div className="bench-donut">
      <svg viewBox="0 0 140 140" width="140" height="140" aria-hidden>
        <circle cx="70" cy="70" r={r} fill="none" stroke="#f0f0f0" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c - dash}`}
          transform="rotate(-90 70 70)"
        />
        <text x="70" y="66" textAnchor="middle" className="bench-donut-val" fill="currentColor">
          {fmtPct(value)}
        </text>
        <text x="70" y="86" textAnchor="middle" className="bench-donut-sub" fill="currentColor">
          {label}
        </text>
      </svg>
      <div className="muted small" style={{ textAlign: "center" }}>
        {sub}
      </div>
    </div>
  );
}

function StackBar({
  blockedOk,
  missed,
  passedOk,
  falsePositive,
}: {
  blockedOk: number;
  missed: number;
  passedOk: number;
  falsePositive: number;
}) {
  const total = Math.max(1, blockedOk + missed + passedOk + falsePositive);
  const segs = [
    { n: blockedOk, color: "#1890ff", label: "TP 检出" },
    { n: missed, color: "#ff4d4f", label: "FN 漏报" },
    { n: passedOk, color: "#52c41a", label: "TN 放行" },
    { n: falsePositive, color: "#fa541c", label: "FP 误报" },
  ];
  return (
    <div className="bench-stack">
      <div className="bench-stack-head">
        <span>混淆矩阵条</span>
        <span className="muted small">TP/FN/TN/FP</span>
      </div>
      <div className="bench-stack-bar">
        {segs.map((s) =>
          s.n > 0 ? (
            <div
              key={s.label}
              title={`${s.label}: ${s.n}`}
              style={{ width: `${(s.n / total) * 100}%`, background: s.color }}
            />
          ) : null,
        )}
      </div>
      <div className="bench-stack-legend">
        {segs.map((s) => (
          <span key={s.label}>
            <i style={{ background: s.color }} />
            {s.label} {s.n.toLocaleString("zh-CN")}
          </span>
        ))}
      </div>
    </div>
  );
}

function laneLabel(lane: string | undefined): string {
  switch (lane) {
    case "api_positive":
      return "API正向";
    case "inline_fast":
      return "内联Fast";
    case "fast":
      return "Fast";
    case "deep":
      return "Deep";
    default:
      return lane || "—";
  }
}

function pathTone(path: string | undefined): NerveTagTone {
  return path === "fast" ? "green" : path === "deep" ? "orange" : "default";
}

export function BenchPage({ health }: Props) {
  const [status, setStatus] = useState<BenchStatus | null>(null);
  const [rows, setRows] = useState<CaseResult[]>([]);
  const [rowTotal, setRowTotal] = useState(0);
  const [engineMetrics, setEngineMetrics] = useState<MetricsSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<BenchDatasetInfo[]>([]);
  const [dataset, setDataset] = useState<BenchDatasetId>("samples");
  const [level, setLevel] = useState<NativeLevel>("medium");
  const [concurrency, setConcurrency] = useState("80");
  const [verdict, setVerdict] = useState("all");
  const [kind, setKind] = useState("all");
  const [busy, setBusy] = useState(false);
  const [pagination, setPagination] = useState<NervePaginationState>(
    defaultPaginationState(),
  );

  const refreshStatus = useCallback(async () => {
    const s = await api.benchStatus();
    setStatus(s);
    setError(null);
    return s;
  }, []);

  const refreshDatasets = useCallback(async () => {
    const out = await api.benchDatasets();
    setDatasets(out.items || []);
  }, []);

  const refreshResults = useCallback(async () => {
    const out = await api.benchResults({
      page: pagination.page,
      page_size: pagination.pageSize,
      verdict,
      kind,
    });
    setRows(out.items);
    setRowTotal(out.total);
  }, [pagination.page, pagination.pageSize, verdict, kind]);

  const refreshEngineMetrics = useCallback(async () => {
    try {
      const m = await api.metrics();
      setEngineMetrics(m);
    } catch {
      /* 非致命 */
    }
  }, []);

  useEffect(() => {
    refreshStatus().catch((e: unknown) => {
      setError(e instanceof Error ? e.message : String(e));
    });
    refreshDatasets().catch(() => {});
  }, [refreshStatus, refreshDatasets]);

  useEffect(() => {
    refreshResults().catch(() => {});
  }, [refreshResults]);

  useEffect(() => {
    if (status?.phase !== "running") return;
    const id = window.setInterval(() => {
      void refreshStatus();
      void refreshResults();
      void refreshEngineMetrics();
    }, 1000);
    return () => window.clearInterval(id);
  }, [status?.phase, refreshStatus, refreshResults, refreshEngineMetrics]);

  useEffect(() => {
    if (status?.phase === "running") return;
    void refreshResults();
    void refreshEngineMetrics();
  }, [status?.phase, refreshResults, refreshEngineMetrics]);

  const running = status?.phase === "running";
  const metrics = status?.metrics;
  const selectedDs = datasets.find((d) => d.id === dataset);

  const onStart = async () => {
    setBusy(true);
    setError(null);
    setPagination((p) => ({ ...p, page: 1 }));
    try {
      if (selectedDs && !selectedDs.ready && dataset !== "samples") {
        throw new Error(
          selectedDs.fetch_hint
            ? `数据源未就绪，请先执行：${selectedDs.fetch_hint}`
            : selectedDs.message || "数据源未就绪",
        );
      }
      const s = await api.benchStart({
        dataset,
        level,
        concurrency: Number(concurrency) || 20,
      });
      setStatus(s);
      await refreshResults();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onStop = async () => {
    setBusy(true);
    try {
      setStatus(await api.benchStop());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onExport = async () => {
    try {
      const report = await api.benchReport();
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `expert-bench-report-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const progress = useMemo(() => {
    if (!status) return 0;
    return Math.min(100, Math.max(0, status.progress_pct || 0));
  }, [status]);

  const columns: NerveTableColumn<Row>[] = [
    {
      key: "idx",
      title: "#",
      render: (row) => <span className="mono small">{row.index + 1}</span>,
    },
    {
      key: "case",
      title: "用例",
      render: (row) => (
        <div>
          <div className="small">
            <NerveTag tone={row.kind === "black" ? "red" : row.kind === "white" ? "green" : "blue"}>
              {row.kind}
            </NerveTag>{" "}
            <strong>{row.name || row.id}</strong>
          </div>
          <div className="muted small break-all">{row.id}</div>
        </div>
      ),
    },
    {
      key: "req",
      title: "请求",
      render: (row) => <code className="small">{row.request_summary}</code>,
    },
    {
      key: "expect",
      title: "期望",
      render: (row) => (
        <NerveTag tone={row.expect === "block" ? "red" : "green"}>{row.expect}</NerveTag>
      ),
    },
    {
      key: "actual",
      title: "实际",
      render: (row) => (
        <div>
          <NerveTag
            tone={
              row.actual === "block"
                ? "red"
                : row.actual === "challenge"
                  ? "blue"
                  : row.actual === "error"
                    ? "orange"
                    : "green"
            }
          >
            {row.actual}
          </NerveTag>
          {row.rule_id ? (
            <div className="muted small" style={{ marginTop: 4 }}>
              {row.rule_id}
            </div>
          ) : null}
        </div>
      ),
    },
    {
      key: "verdict",
      title: "判定",
      render: (row) => (
        <NerveTag tone={row.ok ? "green" : "red"}>{row.ok ? "通过" : "失败"}</NerveTag>
      ),
    },
    {
      key: "perf",
      title: "检测路径",
      render: (row) => (
        <div>
          <NerveTag tone={pathTone(row.inspect_path)}>{row.inspect_path || "—"}</NerveTag>
          <div className="muted small" style={{ marginTop: 4 }}>
            {laneLabel(row.lane)}
            {row.inspect_mode ? ` · ${row.inspect_mode}` : ""}
          </div>
          {row.route_deep ? (
            <div className="muted small">route_deep · score {(row.route_score ?? 0).toFixed(2)}</div>
          ) : row.route_score != null ? (
            <div className="muted small">score {row.route_score.toFixed(2)}</div>
          ) : null}
        </div>
      ),
    },
    {
      key: "ms",
      title: "耗时",
      render: (row) => (
        <div>
          <span className="mono small">{row.elapsed_ms} ms</span>
          {row.budget_exhausted ? (
            <div className="muted small" title={row.budget_exhausted}>
              预算熔断
            </div>
          ) : null}
          {(row.semantic_score ?? 0) > 0 || (row.model_score ?? 0) > 0 ? (
            <div className="muted small">
              sem {row.semantic_score ?? 0} · mdl {row.model_score ?? 0}
            </div>
          ) : null}
        </div>
      ),
    },
  ];

  const tableRows: Row[] = rows.map((r) => ({ ...r }));

  return (
    <div className="bench-page">
      <NervePageHeader
        title="拦截率测试"
        subtitle="用例级自动化：请求 / 期望 / 实际 / 判定 · 报告可导出"
        actions={
          <div className="bench-actions">
            {running ? (
              <NerveButton variant="danger" disabled={busy} onClick={() => void onStop()}>
                停止
              </NerveButton>
            ) : (
              <NerveButton
                variant="primary"
                disabled={busy}
                onClick={() => void onStart()}
              >
                开始测试
              </NerveButton>
            )}
            <NerveButton
              disabled={busy || !(metrics || rowTotal > 0)}
              onClick={() => void onExport()}
            >
              导出报告 JSON
            </NerveButton>
            <NerveButton
              disabled={busy || running}
              onClick={() => {
                void refreshStatus();
                void refreshResults();
              }}
            >
              刷新
            </NerveButton>
          </div>
        }
      />

      {error ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {error}
        </NerveAlert>
      ) : null}

      <div className="bench-hero">
        <div className="bench-hero-main">
          <div className="bench-hero-title-row">
            <h2>测试运行</h2>
            <NerveTag tone={phaseTone(status?.phase ?? "idle")}>
              {phaseLabel(status?.phase ?? "idle")}
            </NerveTag>
          </div>
          <div className="bench-meta-grid">
            <div>
              <div className="muted small">规则包</div>
              <div className="bench-meta-val">
                {status?.pack || health?.pack || "—"}
                {health ? (
                  <span className="muted small"> · {health.rule_count} rules</span>
                ) : null}
              </div>
            </div>
            <div>
              <div className="muted small">数据源</div>
              <div className="bench-meta-val">
                {status?.dataset || dataset}
                <span className="muted small"> · {status?.target || "in-process"}</span>
              </div>
            </div>
            <div>
              <div className="muted small">通过 / 失败</div>
              <div className="bench-meta-val">
                <NerveTag tone="green">{fmtNum(status?.pass_count)}</NerveTag>{" "}
                <NerveTag tone="red">{fmtNum(status?.fail_count)}</NerveTag>
              </div>
            </div>
            <div>
              <div className="muted small">消息</div>
              <div className="bench-meta-val">{status?.message || "—"}</div>
            </div>
          </div>

          {(running || (status && status.total > 0)) && (
            <div className="bench-progress-wrap">
              <div className="bench-progress-head">
                <span>进度</span>
                <span className="mono">
                  {fmtNum(status?.done)} / {fmtNum(status?.total)} · {progress.toFixed(1)}%
                </span>
              </div>
              <div className="bench-progress-track">
                <div
                  className={`bench-progress-fill${running ? " pulse" : ""}`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}
        </div>

        <NerveCard title="测试参数" className="bench-config-card">
          <div className="bench-config">
            <label>
              <span>数据源</span>
              <NerveSelect
                value={dataset}
                disabled={running}
                onChange={(e) => setDataset(e.target.value as BenchDatasetId)}
                options={(datasets.length
                  ? datasets
                  : [
                      {
                        id: "samples" as BenchDatasetId,
                        label: "规则包 samples",
                        ready: true,
                      },
                      {
                        id: "blazehttp" as BenchDatasetId,
                        label: "blazehttp",
                        ready: false,
                      },
                      {
                        id: "gotestwaf" as BenchDatasetId,
                        label: "GoTestWAF",
                        ready: false,
                      },
                      {
                        id: "waftester" as BenchDatasetId,
                        label: "WAFtester",
                        ready: false,
                      },
                      {
                        id: "crs-ftw" as BenchDatasetId,
                        label: "CRS/FTW",
                        ready: false,
                      },
                    ]
                ).map((d) => ({
                  value: d.id,
                  label: `${d.ready ? "●" : "○"} ${d.label}`,
                }))}
              />
            </label>
            <label>
              <span>防护级别</span>
              <NerveSelect
                value={level}
                disabled={running}
                onChange={(e) => setLevel(e.target.value as NativeLevel)}
                options={[
                  { value: "low", label: "low · 宽松" },
                  { value: "medium", label: "medium · 中等" },
                  { value: "high", label: "high · 严格" },
                ]}
              />
            </label>
            <label>
              <span>并发</span>
              <NerveSelect
                value={concurrency}
                disabled={running}
                onChange={(e) => setConcurrency(e.target.value)}
                options={[
                  { value: "10", label: "10" },
                  { value: "40", label: "40" },
                  { value: "80", label: "80（推荐）" },
                  { value: "120", label: "120" },
                ]}
              />
            </label>
          </div>
          <div className="bench-dataset-meta">
            {selectedDs ? (
              <>
                <NerveTag tone={selectedDs.ready ? "green" : "orange"}>
                  {selectedDs.ready ? "就绪" : "未就绪"}
                </NerveTag>
                <span className="muted small">{selectedDs.description}</span>
                {!selectedDs.ready && selectedDs.fetch_hint ? (
                  <code className="small">{selectedDs.fetch_hint}</code>
                ) : null}
              </>
            ) : (
              <span className="muted small">
                samples / blazehttp / GoTestWAF / WAFtester / CRS-FTW · 进程内
                engine.inspect
              </span>
            )}
            <NerveButton disabled={running} onClick={() => void refreshDatasets()}>
              刷新数据源
            </NerveButton>
          </div>
        </NerveCard>
      </div>

      {metrics ? (
        <>
          <div className="bench-kpi-grid">
            <div className="bench-kpi accent-detect">
              <div className="bench-kpi-label">检出率</div>
              <div className="bench-kpi-num">{fmtPct(metrics.detection_rate)}</div>
              <div className="muted small">
                拦截 {fmtNum(metrics.blocked_ok)} / 恶意 {fmtNum(metrics.malicious_total)}
              </div>
            </div>
            <div className="bench-kpi accent-fp">
              <div className="bench-kpi-label">误报率</div>
              <div className="bench-kpi-num">{fmtPct(metrics.false_positive_rate)}</div>
              <div className="muted small">
                误拦 {fmtNum(metrics.false_positive)} / 正常 {fmtNum(metrics.normal_total)}
              </div>
            </div>
            <div className="bench-kpi accent-acc">
              <div className="bench-kpi-label">准确率</div>
              <div className="bench-kpi-num">{fmtPct(metrics.accuracy)}</div>
              <div className="muted small">
                用例通过 {fmtNum(metrics.pass_count)} · 失败 {fmtNum(metrics.fail_count)}
              </div>
            </div>
            <div className="bench-kpi">
              <div className="bench-kpi-label">平均耗时</div>
              <div className="bench-kpi-num">
                {metrics.avg_ms != null ? metrics.avg_ms.toFixed(1) : "—"}
                <span className="bench-kpi-unit">ms</span>
              </div>
              <div className="muted small">
                Fast {metrics.avg_fast_ms != null ? metrics.avg_fast_ms.toFixed(1) : "—"} ms · Deep{" "}
                {metrics.avg_deep_ms != null ? metrics.avg_deep_ms.toFixed(1) : "—"} ms
                {metrics.max_ms != null ? ` · max ${metrics.max_ms} ms` : ""}
              </div>
            </div>
            <div className="bench-kpi">
              <div className="bench-kpi-label">Fast 占比</div>
              <div className="bench-kpi-num">
                {metrics.fast_path_ratio != null
                  ? `${(metrics.fast_path_ratio * 100).toFixed(1)}%`
                  : "—"}
              </div>
              <div className="muted small">
                fast {fmtNum(metrics.fast_path_count)} · deep {fmtNum(metrics.deep_path_count)}
                {metrics.budget_exhausted_count
                  ? ` · 熔断 ${fmtNum(metrics.budget_exhausted_count)}`
                  : ""}
                {status?.elapsed_ms != null
                  ? ` · 墙钟 ${(status.elapsed_ms / 1000).toFixed(1)}s`
                  : ""}
              </div>
            </div>
          </div>

          {engineMetrics ? (
            <NerveCard title="引擎运行时指标" tip="GET /api/metrics · 判断路由 vs 池/算力">
              <div className="bench-mini-stats">
                <div>
                  <strong>
                    {engineMetrics.inspect_total
                      ? `${((engineMetrics.fast_ratio ?? engineMetrics.inspect_fast / engineMetrics.inspect_total) * 100).toFixed(1)}%`
                      : "—"}
                  </strong>
                  <span>fast_ratio</span>
                </div>
                <div>
                  <strong>{(engineMetrics.latency_fast_us_avg / 1000).toFixed(1)} ms</strong>
                  <span>fast_avg</span>
                </div>
                <div>
                  <strong>{(engineMetrics.latency_deep_us_avg / 1000).toFixed(1)} ms</strong>
                  <span>deep_avg</span>
                </div>
                <div>
                  <strong>{engineMetrics.fast_pool_escalate}</strong>
                  <span>pool_escalate</span>
                </div>
                <div>
                  <strong>{engineMetrics.budget_exhausted}</strong>
                  <span>budget_out</span>
                </div>
                <div>
                  <strong>{(engineMetrics.route_gate_deep_ratio * 100).toFixed(1)}%</strong>
                  <span>route_deep</span>
                </div>
              </div>
              <p className="muted small" style={{ marginTop: 8, marginBottom: 0 }}>
                脚本诊断：<code>bash scripts/check-inspect-metrics.sh</code>
              </p>
            </NerveCard>
          ) : null}

          <div className="bench-charts" style={{ marginBottom: 16 }}>
            <NerveCard title="报表图表">
              <div className="bench-donut-row">
                <Donut
                  value={metrics.detection_rate}
                  color="#1890ff"
                  label="检出率"
                  sub={`漏报 ${fmtNum(metrics.missed)}`}
                />
                <Donut
                  value={metrics.false_positive_rate}
                  color="#fa541c"
                  label="误报率"
                  sub={`误拦 ${fmtNum(metrics.false_positive)}`}
                />
                <Donut
                  value={metrics.accuracy}
                  color="#52c41a"
                  label="准确率"
                  sub={`失败用例 ${fmtNum(metrics.fail_count)}`}
                />
              </div>
            </NerveCard>
            <NerveCard title="结果分布" tip={status?.dataset || undefined}>
              <StackBar
                blockedOk={metrics.blocked_ok || 0}
                missed={metrics.missed || 0}
                passedOk={metrics.passed_ok || 0}
                falsePositive={metrics.false_positive || 0}
              />
              <div className="bench-mini-stats">
                <div>
                  <strong>{fmtNum(metrics.malicious_total)}</strong>
                  <span>恶意样本</span>
                </div>
                <div>
                  <strong>{fmtNum(metrics.normal_total)}</strong>
                  <span>正常样本</span>
                </div>
                <div>
                  <strong>{fmtNum(metrics.total)}</strong>
                  <span>合计 · {status?.dataset || "—"}</span>
                </div>
              </div>
            </NerveCard>
          </div>
        </>
      ) : null}

      <NerveCard
        title="用例明细"
        tip={
          running
            ? "执行中实时刷新"
            : rowTotal
              ? `共 ${rowTotal} 条（当前筛选）`
              : undefined
        }
      >
        <NerveTableToolbar>
          <NerveSelect
            value={verdict}
            onChange={(e) => {
              setVerdict(e.target.value);
              setPagination((p) => ({ ...p, page: 1 }));
            }}
            options={[
              { value: "all", label: "全部判定" },
              { value: "fail", label: "仅失败" },
              { value: "pass", label: "仅通过" },
            ]}
          />
          <NerveSelect
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setPagination((p) => ({ ...p, page: 1 }));
            }}
            options={[
              { value: "all", label: "全部类型" },
              { value: "sample", label: "sample" },
              { value: "black", label: "black" },
              { value: "white", label: "white" },
            ]}
          />
        </NerveTableToolbar>

        {rowTotal === 0 && !running ? (
          <NerveEmpty description="点击「开始测试」后，每条用例的期望与实际会出现在此表" />
        ) : (
          <>
            <NerveTable
              columns={columns}
              dataSource={tableRows}
              rowKey={(r) => `${r.index}-${r.id}`}
              emptyText={running ? "结果写入中…" : "无匹配用例"}
            />
            <NervePagination
              total={rowTotal}
              page={pagination.page}
              pageSize={pagination.pageSize}
              onChange={setPagination}
            />
          </>
        )}
      </NerveCard>
    </div>
  );
}
