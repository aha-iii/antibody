import { useCallback, useEffect, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NervePageHeader,
  NerveTable,
  NerveTag,
  type NerveTableColumn,
} from "@nerve/ui";
import { api, type Health, type MetricsSnapshot } from "../api";

type Props = {
  health: Health | null;
};

function pct(part: number, total: number): string {
  if (!total) return "0%";
  return `${((part / total) * 100).toFixed(1)}%`;
}

function usToMs(us: number): string {
  if (us <= 0) return "0";
  if (us < 1000) return `${us}µs`;
  return `${(us / 1000).toFixed(2)}ms`;
}

type RuleRow = { rule_id: string; hits: number } & Record<string, unknown>;

const RULE_COLUMNS: NerveTableColumn<RuleRow>[] = [
  {
    key: "rule_id",
    title: "规则 ID",
    render: (row) => <code className="cr-id">{String(row.rule_id)}</code>,
  },
  {
    key: "hits",
    title: "命中次数",
    render: (row) => (
      <strong className="mono">{Number(row.hits).toLocaleString()}</strong>
    ),
  },
];

export function MetricsPage({ health }: Props) {
  const [m, setM] = useState<MetricsSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setM(await api.metrics());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(t);
  }, [refresh]);

  const total = m?.inspect_total ?? 0;
  const budgetRatio = total > 0 && m ? m.budget_exhausted / total : 0;

  return (
    <div>
      <NervePageHeader
        title="可观测"
        subtitle="引擎运行时指标（GET /api/metrics）"
        actions={
          <NerveButton disabled={loading} onClick={() => void refresh()}>
            刷新
          </NerveButton>
        }
      />

      {error ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {error}
        </NerveAlert>
      ) : null}

      <div className="muted small" style={{ marginBottom: 12 }}>
        pack={health?.pack ?? "—"} · mode={health?.inspect_mode ?? "—"} · accel=
        {health?.accel ?? "—"} · 每 5s 自动刷新
      </div>

      <div className="expert-stat-grid">
        <NerveCard title="Inspect 总量">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {m ? m.inspect_total.toLocaleString() : "—"}
            </strong>
            <div className="muted small">
              hit={m?.inspect_hit ?? 0} · block={m?.inspect_block ?? 0} ·
              challenge={m?.inspect_challenge ?? 0} · observe=
              {m?.inspect_observe ?? 0}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="Fast / Deep">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {m ? pct(m.inspect_fast, total) : "—"}
              <span className="muted" style={{ fontSize: 14, margin: "0 6px" }}>
                /
              </span>
              {m ? pct(m.inspect_deep, total) : "—"}
            </strong>
            <div className="muted small">
              fast={m?.inspect_fast ?? 0} · deep={m?.inspect_deep ?? 0}
              {m ? ` · route_deep=${(m.route_gate_deep_ratio * 100).toFixed(1)}%` : ""}
            </div>
            {m && total > 0 ? (
              <div className="bench-stack-bar" style={{ marginTop: 10 }}>
                <div
                  className="bench-stack-seg"
                  style={{
                    width: pct(m.inspect_fast, total),
                    background: "#1890ff",
                  }}
                />
                <div
                  className="bench-stack-seg"
                  style={{
                    width: pct(m.inspect_deep, total),
                    background: "#722ed1",
                  }}
                />
              </div>
            ) : null}
          </div>
        </NerveCard>
        <NerveCard title="延迟 avg / max">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {m ? usToMs(m.latency_us_avg) : "—"}
            </strong>
            <div className="muted small">
              max={m ? usToMs(m.latency_us_max) : "—"} · fast_avg=
              {m ? usToMs(m.latency_fast_us_avg) : "—"} · deep_avg=
              {m ? usToMs(m.latency_deep_us_avg) : "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="Budget 熔断">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {m ? m.budget_exhausted.toLocaleString() : "—"}
            </strong>
            <div className="muted small">
              占比{" "}
              <NerveTag tone={budgetRatio > 0.01 ? "red" : "green"}>
                {(budgetRatio * 100).toFixed(2)}%
              </NerveTag>
              {" · "}
              SLO 参考 &lt;1%
            </div>
          </div>
        </NerveCard>
        <NerveCard title="Shadow">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {m ? m.shadow_done.toLocaleString() : "—"}
            </strong>
            <div className="muted small">
              would_hit={m?.shadow_would_hit ?? 0} · dropped=
              {m?.shadow_dropped ?? 0} · escalate={m?.fast_pool_escalate ?? 0}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="预算上限">
          <div className="expert-stat">
            <strong>{health?.max_inspect_ms ?? "—"}ms</strong>
            <div className="muted small">
              fast_max={health?.fast_max_inspect_ms ?? "—"} · pipeline decode=
              {String(health?.pipeline_decode ?? "—")} / structural=
              {String(health?.pipeline_structural ?? "—")}
            </div>
          </div>
        </NerveCard>
      </div>

      <div className="expert-stat-grid" style={{ marginTop: 16 }}>
        <NerveCard title="Stage 耗时（avg）">
          {!m ? (
            <NerveEmpty description="暂无数据" sm />
          ) : (
            <div className="bench-mini-stats" style={{ marginTop: 0 }}>
              <div>
                <strong>{usToMs(m.stage_decode_us_avg)}</strong>
                <span>decode</span>
              </div>
              <div>
                <strong>{usToMs(m.stage_aho_us_avg)}</strong>
                <span>aho</span>
              </div>
              <div>
                <strong>{usToMs(m.stage_regex_us_avg)}</strong>
                <span>regex</span>
              </div>
              <div>
                <strong>{usToMs(m.stage_semantic_us_avg)}</strong>
                <span>semantic</span>
              </div>
              <div>
                <strong>{usToMs(m.stage_fusion_us_avg)}</strong>
                <span>fusion</span>
              </div>
            </div>
          )}
        </NerveCard>
        <NerveCard title="延迟分桶" tip="le_1ms … le_inf">
          {!m?.latency_buckets?.length ? (
            <NerveEmpty description="暂无分桶" sm />
          ) : (
            <div className="bench-mini-stats" style={{ marginTop: 0 }}>
              {[
                "≤1ms",
                "≤5ms",
                "≤20ms",
                "≤50ms",
                "≤200ms",
                "≤1.2s",
                "inf",
              ].map((label, i) => (
                <div key={label}>
                  <strong>{(m.latency_buckets[i] ?? 0).toLocaleString()}</strong>
                  <span>{label}</span>
                </div>
              ))}
            </div>
          )}
        </NerveCard>
      </div>

      <NerveCard title="Top Rules" style={{ marginTop: 16 }}>
        {!m?.top_rules?.length ? (
          <NerveEmpty description="尚无规则命中统计（试打或压测后会出现）" />
        ) : (
          <NerveTable
            columns={RULE_COLUMNS}
            dataSource={m.top_rules.map((r) => ({ ...r }))}
            rowKey="rule_id"
          />
        )}
      </NerveCard>
    </div>
  );
}
