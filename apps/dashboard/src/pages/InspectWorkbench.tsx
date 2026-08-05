import { useCallback, useEffect, useRef, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveForm,
  NerveFormItem,
  NerveInput,
  NervePagination,
  NerveSelect,
  NerveTable,
  NerveTableToolbar,
  NerveTag,
  NerveTextarea,
  defaultPaginationState,
  paginate,
  type NervePaginationState,
  type NerveTableColumn,
  type NerveTagTone,
} from "@nerve/ui";
import {
  api,
  type NativeHit,
  type NativeLevel,
  type Health,
  type InspectResult,
  type MatchedRule,
  type PackInfo,
  type SampleCase,
} from "../api";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;
const LEVELS: NativeLevel[] = ["low", "medium", "high"];

type FormState = {
  pack: string;
  level: NativeLevel;
  method: string;
  host: string;
  uri: string;
  query: string;
  headersText: string;
  body: string;
};

const INITIAL: FormState = {
  pack: "",
  level: "medium",
  method: "GET",
  host: "example.com",
  uri: "/search",
  query: "q=hello",
  headersText: JSON.stringify(
    {
      "User-Agent": "dashboard/1.0",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    null,
    2,
  ),
  body: "",
};

type MatchedRow = MatchedRule & Record<string, unknown>;

function actionTone(action: string): NerveTagTone {
  if (action === "block") return "red";
  if (action === "observe") return "orange";
  return "green";
}

const MATCH_COLUMNS: NerveTableColumn<MatchedRow>[] = [
  {
    key: "rule",
    title: "规则",
    render: (row) => (
      <div>
        <div>
          <code>{row.rule_id}</code>
        </div>
        <div className="muted small">{row.rule_name}</div>
      </div>
    ),
  },
  {
    key: "severity",
    title: "严重度",
    render: (row) => (
      <span className="small">{String(row.severity).toUpperCase()}</span>
    ),
  },
  { key: "score", title: "分", dataIndex: "score" },
  {
    key: "action",
    title: "动作",
    render: (row) => (
      <NerveTag tone={actionTone(String(row.action))}>{row.action}</NerveTag>
    ),
  },
  { key: "evidence", title: "证据", dataIndex: "evidence" },
];

function formFromSample(
  sample: SampleCase,
  packFallback: string,
): FormState {
  const r = sample.request;
  const level = (
    ["low", "medium", "high"].includes(sample.min_level)
      ? sample.min_level
      : "medium"
  ) as NativeLevel;
  return {
    pack: packFallback,
    level,
    method: r.method || "GET",
    host: r.host || "example.com",
    uri: r.uri || "/",
    query: r.query || "",
    headersText: JSON.stringify(r.headers || {}, null, 2),
    body: r.body || "",
  };
}

export type InspectWorkbenchProps = {
  health: Health | null;
  packs: PackInfo[];
  onHealth: (h: Health) => void;
  onPacksRefresh: () => Promise<void>;
  /** 打开时预填的案例 */
  sample?: SampleCase | null;
  /** 预填后自动跑一次 inspect */
  autoInspect?: boolean;
};

/** 完整「请求 + 结果」工作台（页面或弹框内复用） */
export function InspectWorkbench({
  health,
  packs,
  onHealth,
  onPacksRefresh,
  sample = null,
  autoInspect = false,
}: InspectWorkbenchProps) {
  const [form, setForm] = useState<FormState>(INITIAL);
  const [actionError, setActionError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectResult | null>(null);
  const [busy, setBusy] = useState<"inspect" | "reload" | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const autoKey = useRef<string>("");

  useEffect(() => {
    if (!form.pack && (health?.pack || packs[0]?.id)) {
      setForm((prev) => ({
        ...prev,
        pack:
          health?.pack ||
          packs.find((p) => p.current)?.id ||
          packs[0]?.id ||
          "",
      }));
    }
  }, [health, packs, form.pack]);

  const runInspect = useCallback(
    async (state: FormState) => {
      setBusy("inspect");
      setActionError(null);
      try {
        let headers: Record<string, string>;
        try {
          const parsed = JSON.parse(state.headersText || "{}") as unknown;
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("headers 必须是 JSON 对象");
          }
          headers = parsed as Record<string, string>;
        } catch (e: unknown) {
          throw new Error(
            `Headers JSON 无效：${e instanceof Error ? e.message : String(e)}`,
          );
        }

        const current = packs.find((p) => p.current);
        if (current && state.pack && current.id !== state.pack) {
          const h = await api.reload(state.pack);
          onHealth(h);
          await onPacksRefresh();
        }

        const out = await api.inspect({
          method: state.method,
          host: state.host,
          uri: state.uri,
          query: state.query,
          headers,
          body: state.body,
          level: state.level,
        });
        setResult(out);
      } catch (e: unknown) {
        setActionError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(null);
      }
    },
    [packs, onHealth, onPacksRefresh],
  );

  useEffect(() => {
    if (!sample) return;
    const pack =
      health?.pack ||
      packs.find((p) => p.current)?.id ||
      packs[0]?.id ||
      form.pack ||
      "baseline";
    const next = formFromSample(sample, pack);
    setForm(next);
    setHint(
      `${sample.id} · ${sample.rule_id || "clean"} · expect ${sample.expect_action}`,
    );
    setResult(null);
    setActionError(null);

    const key = `${sample.id}:${autoInspect ? "1" : "0"}`;
    if (autoInspect && autoKey.current !== key) {
      autoKey.current = key;
      void runInspect(next);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only react to sample identity
  }, [sample?.id]);

  const setField = <K extends keyof FormState>(key: K, value: FormState[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const onReload = useCallback(async () => {
    setBusy("reload");
    setActionError(null);
    try {
      const h = await api.reload(form.pack);
      onHealth(h);
      await onPacksRefresh();
      setResult(null);
    } catch (e: unknown) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }, [form.pack, onHealth, onPacksRefresh]);

  return (
    <div className="expert-workbench">
      <div className="expert-workbench-toolbar">
        <NerveTableToolbar>
          <NerveButton
            variant="primary"
            disabled={busy !== null}
            onClick={() => void runInspect(form)}
          >
            {busy === "inspect" ? "检测中…" : "检测"}
          </NerveButton>
          <NerveButton
            disabled={busy !== null || !form.pack}
            onClick={() => void onReload()}
          >
            {busy === "reload" ? "重载中…" : "切换 / 重载包"}
          </NerveButton>
        </NerveTableToolbar>
      </div>

      {hint ? (
        <NerveAlert tone="info" style={{ marginBottom: 12 }}>
          案例：{hint}
        </NerveAlert>
      ) : null}

      {actionError ? (
        <NerveAlert tone="error" style={{ marginBottom: 12 }}>
          {actionError}
        </NerveAlert>
      ) : null}

      <div className="expert-split">
        <NerveCard title="请求" tip="HTTP 视图">
          <NerveForm>
            <div className="expert-row-3">
              <NerveFormItem label="Pack">
                <NerveSelect
                  wide
                  value={form.pack}
                  onChange={(e) => setField("pack", e.target.value)}
                  options={
                    packs.length
                      ? packs.map((p) => ({
                          value: p.id,
                          label: p.current ? `${p.id} (current)` : p.id,
                        }))
                      : [{ value: "", label: "—" }]
                  }
                />
              </NerveFormItem>
              <NerveFormItem label="Level">
                <NerveSelect
                  wide
                  value={form.level}
                  onChange={(e) =>
                    setField("level", e.target.value as NativeLevel)
                  }
                  options={LEVELS.map((l) => ({ value: l, label: l }))}
                />
              </NerveFormItem>
              <NerveFormItem label="Method">
                <NerveSelect
                  wide
                  value={form.method}
                  onChange={(e) => setField("method", e.target.value)}
                  options={METHODS.map((m) => ({ value: m, label: m }))}
                />
              </NerveFormItem>
            </div>

            <div className="expert-row-2">
              <NerveFormItem label="Host">
                <NerveInput
                  wide
                  value={form.host}
                  onChange={(e) => setField("host", e.target.value)}
                />
              </NerveFormItem>
              <NerveFormItem label="URI">
                <NerveInput
                  wide
                  value={form.uri}
                  onChange={(e) => setField("uri", e.target.value)}
                />
              </NerveFormItem>
            </div>

            <NerveFormItem label="Query">
              <NerveInput
                wide
                value={form.query}
                onChange={(e) => setField("query", e.target.value)}
              />
            </NerveFormItem>

            <NerveFormItem label="Headers (JSON)">
              <NerveTextarea
                rows={4}
                spellCheck={false}
                value={form.headersText}
                onChange={(e) => setField("headersText", e.target.value)}
              />
            </NerveFormItem>

            <NerveFormItem label="Body">
              <NerveTextarea
                rows={3}
                spellCheck={false}
                value={form.body}
                onChange={(e) => setField("body", e.target.value)}
              />
            </NerveFormItem>
          </NerveForm>
        </NerveCard>

        <NerveCard
          title="结果"
          tip={
            result
              ? `${result.elapsed_ms} ms · ${result.pack} · ${result.level}`
              : busy === "inspect"
                ? "检测中…"
                : "等待检测"
          }
        >
          <ResultPanel result={result} />
        </NerveCard>
      </div>
    </div>
  );
}

function ResultPanel({ result }: { result: InspectResult | null }) {
  if (!result) {
    return (
      <NerveEmpty
        description="尚未检测"
        hint="编辑请求后点击「检测」"
      />
    );
  }

  const hit = result.hit;
  if (!hit) {
    return (
      <div>
        <div className="expert-result-hero">
          <NerveTag tone="green">PASS</NerveTag>
          <span className="muted small">
            {result.elapsed_ms} ms · pack={result.pack} · level={result.level}
          </span>
        </div>
        <NerveEmpty description="未命中任何规则" sm />
      </div>
    );
  }

  return <HitView hit={hit} result={result} />;
}

function HitView({ hit, result }: { hit: NativeHit; result: InspectResult }) {
  const [pagination, setPagination] = useState<NervePaginationState>(
    defaultPaginationState(),
  );
  const pct = Math.min(
    100,
    Math.round((hit.total_score / Math.max(hit.block_threshold, 1)) * 100),
  );
  const rows: MatchedRow[] = (hit.matched ?? []).map((m) => ({ ...m }));
  const pageRows = paginate(rows, pagination.page, pagination.pageSize);

  useEffect(() => {
    setPagination((p) => ({ ...p, page: 1 }));
  }, [hit.rule_id, hit.total_score, hit.matched.length]);

  return (
    <div>
      <div className="expert-result-hero">
        <NerveTag tone={actionTone(hit.action)}>
          {hit.action.toUpperCase()}
        </NerveTag>
        <span className="muted small">
          {result.elapsed_ms} ms · pack={result.pack} · level={result.level}
        </span>
      </div>

      <div className="expert-score">
        <div className="expert-score-head">
          <span className="muted">融合评分</span>
          <strong>
            {hit.total_score} / {hit.block_threshold}
          </strong>
        </div>
        <div className="expert-score-bar">
          <div className="expert-score-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="muted small" style={{ marginTop: 8 }}>
          rule={hit.rule_score ?? "—"} − allow={hit.allow_score ?? 0} + sem=
          {hit.semantic_score ?? 0} + model={hit.model_score ?? 0}
          {hit.model?.contributed === false && hit.model?.model_score
            ? " (model shadow)"
            : ""}
        </div>
      </div>

      <NerveTable
        columns={MATCH_COLUMNS}
        dataSource={pageRows}
        rowKey={(row, i) => `${row.rule_id}-${i}`}
        emptyText="无命中明细"
      />
      <NervePagination
        total={rows.length}
        page={pagination.page}
        pageSize={pagination.pageSize}
        onChange={setPagination}
      />
    </div>
  );
}
