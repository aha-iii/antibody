import { useCallback, useEffect, useMemo, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveFormItem,
  NerveInput,
  NerveModal,
  NervePageHeader,
  NerveSelect,
  NerveSwitch,
  NerveTable,
  NerveTableToolbar,
  NerveTag,
  nerveToast,
  type NerveTableColumn,
} from "@nerve/ui";
import {
  api,
  type AdmissionConfig,
  type ExpertOverlay,
  type Health,
  type PackInfo,
  type RuleRow,
  type RuleSetRow,
} from "../api";

type SharedProps = {
  health: Health | null;
  packs: PackInfo[];
  onRefresh: () => Promise<void>;
};

function useOverlay() {
  const [overlay, setOverlay] = useState<ExpertOverlay | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      setOverlay(await api.overlay());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (next: ExpertOverlay) => {
    setSaving(true);
    try {
      const saved = await api.putOverlay(next);
      setOverlay(saved);
      nerveToast("已保存");
    } catch (e) {
      nerveToast(e instanceof Error ? e.message : String(e), false);
    } finally {
      setSaving(false);
    }
  };

  return { overlay, setOverlay, error, saving, load, save };
}

export function OverviewPage({ health, packs }: SharedProps) {
  const { overlay, error } = useOverlay();
  return (
    <div>
      <NervePageHeader title="总览" />
      {error ? <NerveAlert tone="error">{error}</NerveAlert> : null}
      <div className="expert-stat-grid">
        <NerveCard title="规则包">
          <div className="expert-stat">
            <strong>{health?.pack ?? "—"}</strong>
            <div className="muted small">
              {health?.pack_version ?? ""} · {health?.rule_count ?? 0} 条规则
            </div>
          </div>
        </NerveCard>
        <NerveCard title="防护粒度">
          <div className="expert-stat">
            <strong>{String(overlay?.level ?? "—")}</strong>
            <div className="muted small">
              已禁用规则 {overlay?.disabled_rule_ids.length ?? 0} 条 · mode=
              {health?.inspect_mode ?? "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="阈值三档">
          <div className="expert-stat">
            <strong>
              {health?.threshold_low ?? "—"}/
              {health?.threshold_medium ?? health?.block_threshold ?? "—"}/
              {health?.threshold_high ?? "—"}
            </strong>
            <div className="muted small">
              low/medium/high · rules L/M/H=
              {health?.rules_low ?? "—"}/{health?.rules_medium ?? "—"}/
              {health?.rules_high ?? "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="语义 / 算法">
          <div className="expert-stat">
            <strong>
              {health?.semantic_enabled ? "ON" : "OFF"} /{" "}
              {health?.adaptive_enabled ? "ON" : "OFF"}
            </strong>
            <div className="muted small">
              model={health?.model_version || "—"} · signals=
              {health?.signals_feature_count ?? 0}f/
              {health?.signals_fingerprint_count ?? 0}fp
            </div>
          </div>
        </NerveCard>
        <NerveCard title="加速">
          <div className="expert-stat">
            <code>{health?.accel ?? "—"}</code>
            <div className="muted small">
              max_inspect={health?.max_inspect_ms ?? "—"}ms
            </div>
          </div>
        </NerveCard>
        <NerveCard title="本地规则包">
          <div className="expert-stat">
            <strong>{packs.length}</strong>
            <div className="muted small">packs 目录可切换（引擎状态）</div>
          </div>
        </NerveCard>
      </div>
    </div>
  );
}

type PackRulesModalProps = {
  open: boolean;
  ruleSetId: string;
  ruleSetName: string;
  onClose: () => void;
  /** 规则启用状态变更后回调，用于刷新规则集卡片计数 */
  onChanged?: () => void;
};

function RuleDocModal({
  rule,
  onClose,
}: {
  rule: RuleRow | null;
  onClose: () => void;
}) {
  const doc = rule?.doc;
  return (
    <NerveModal
      open={!!rule && !!doc}
      wide
      title={rule ? `${rule.id} · 规则说明` : "规则说明"}
      onClose={onClose}
      footer={<NerveButton variant="primary" onClick={onClose}>关闭</NerveButton>}
    >
      {doc ? (
        <div className="rule-doc-panel">
          <section>
            <h4 className="rule-doc-heading">摘要</h4>
            <p>{doc.summary}</p>
          </section>
          {doc.detects ? (
            <section>
              <h4 className="rule-doc-heading">检测说明</h4>
              <pre className="rule-doc-pre">{doc.detects}</pre>
            </section>
          ) : null}
          {doc.block_examples && doc.block_examples.length > 0 ? (
            <section>
              <h4 className="rule-doc-heading">应拦截示例</h4>
              <ul className="rule-doc-list">
                {doc.block_examples.map((ex) => (
                  <li key={ex}>
                    <code>{ex}</code>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          {doc.pass_examples && doc.pass_examples.length > 0 ? (
            <section>
              <h4 className="rule-doc-heading">应放行示例</h4>
              <ul className="rule-doc-list">
                {doc.pass_examples.map((ex) => (
                  <li key={ex}>
                    <code>{ex}</code>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
          {doc.notes ? (
            <section>
              <h4 className="rule-doc-heading">备注</h4>
              <p className="muted small">{doc.notes}</p>
            </section>
          ) : null}
        </div>
      ) : null}
    </NerveModal>
  );
}

function PackRulesModal({
  open,
  ruleSetId,
  ruleSetName,
  onClose,
  onChanged,
}: PackRulesModalProps) {
  const { overlay, save, saving, load } = useOverlay();
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(false);
  const [enabledCount, setEnabledCount] = useState(0);
  const [docRule, setDocRule] = useState<RuleRow | null>(null);

  const refreshRules = useCallback(async () => {
    if (!ruleSetId) return;
    const out = await api.rules({ set: ruleSetId });
    setRules(out.rules);
    setEnabledCount(out.enabled_count);
  }, [ruleSetId]);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setLoading(true);
    void Promise.all([load(), refreshRules()])
      .catch((e: unknown) =>
        nerveToast(e instanceof Error ? e.message : String(e), false),
      )
      .finally(() => setLoading(false));
  }, [open, load, refreshRules]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rules;
    const docMatches = (r: RuleRow) => {
      const d = r.doc;
      if (!d) return false;
      if (d.summary.toLowerCase().includes(s)) return true;
      if (d.detects?.toLowerCase().includes(s)) return true;
      if (d.notes?.toLowerCase().includes(s)) return true;
      if (d.block_examples?.some((ex) => ex.toLowerCase().includes(s))) return true;
      if (d.pass_examples?.some((ex) => ex.toLowerCase().includes(s))) return true;
      return false;
    };
    return rules.filter(
      (r) =>
        r.id.toLowerCase().includes(s) ||
        r.name.toLowerCase().includes(s) ||
        r.tags.some((t) => t.toLowerCase().includes(s)) ||
        docMatches(r),
    );
  }, [rules, q]);

  const toggle = async (id: string, enabled: boolean) => {
    if (!overlay) return;
    const set = new Set(overlay.disabled_rule_ids);
    if (enabled) set.delete(id);
    else set.add(id);
    await save({ ...overlay, disabled_rule_ids: [...set] });
    await refreshRules();
    onChanged?.();
  };

  const columns: NerveTableColumn<RuleRow & Record<string, unknown>>[] = [
    {
      key: "id",
      title: "ID",
      render: (row) => <span className="cr-id">{String(row.id)}</span>,
    },
    {
      key: "name",
      title: "名称",
      render: (row) => (
        <span className="cr-rule-name">
          {String(row.name)}
          {row.doc?.summary ? (
            <span className="muted small rule-doc-inline">{row.doc.summary}</span>
          ) : null}
        </span>
      ),
    },
    {
      key: "doc",
      title: "说明",
      render: (row) =>
        row.doc ? (
          <NerveButton variant="link" onClick={() => setDocRule(row as RuleRow)}>
            查看
          </NerveButton>
        ) : (
          <span className="muted small">—</span>
        ),
    },
    { key: "min_level", title: "最低档", dataIndex: "min_level" },
    {
      key: "action",
      title: "动作",
      render: (row) => (
        <NerveTag
          tone={
            row.action === "block" ? "red" : row.action === "allow" ? "green" : "blue"
          }
        >
          {String(row.action)}
        </NerveTag>
      ),
    },
    {
      key: "enabled",
      title: "启用",
      render: (row) => (
        <NerveSwitch
          checked={!!row.enabled}
          disabled={saving}
          onChange={(e) => void toggle(String(row.id), e.target.checked)}
        />
      ),
    },
  ];

  return (
    <>
      <RuleDocModal rule={docRule} onClose={() => setDocRule(null)} />
      <NerveModal
        open={open}
        wide
        title={`${ruleSetName} · 规则`}
        onClose={onClose}
        footer={<NerveButton variant="primary" onClick={onClose}>关闭</NerveButton>}
      >
        {loading ? <div className="page-loading">加载规则…</div> : null}
        {!loading ? (
          <>
            <div className="muted small" style={{ marginBottom: 8 }}>
              启用 {enabledCount}/{rules.length}
            </div>
            <NerveTableToolbar>
              <NerveInput
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="搜索 ID / 名称 / 标签 / 说明"
                wide
              />
            </NerveTableToolbar>
            {filtered.length === 0 ? (
              <NerveEmpty description="该规则集暂无规则" />
            ) : (
              <NerveTable
                columns={columns}
                dataSource={filtered.map((r) => ({ ...r }))}
                rowKey="id"
                className="cr-table"
              />
            )}
          </>
        ) : null}
      </NerveModal>
    </>
  );
}

export function PacksPage({ health, onRefresh }: SharedProps) {
  const { overlay, save, saving, load } = useOverlay();
  const [sets, setSets] = useState<RuleSetRow[]>([]);
  const [pack, setPack] = useState("");
  const [rulesModal, setRulesModal] = useState<{
    id: string;
    name: string;
  } | null>(null);

  const refresh = useCallback(async () => {
    const out = await api.ruleSets();
    setSets(out.sets);
    setPack(out.pack);
  }, []);

  useEffect(() => {
    void refresh().catch((e: unknown) =>
      nerveToast(e instanceof Error ? e.message : String(e), false),
    );
  }, [refresh]);

  const toggleSet = async (id: string, enabled: boolean) => {
    if (!overlay) return;
    const cats = new Set(overlay.disabled_categories);
    if (enabled) cats.delete(id);
    else cats.add(id);
    await save({ ...overlay, disabled_categories: [...cats] });
    await refresh();
  };

  return (
    <div className="cr-page">
      <NervePageHeader
        title="规则集"
        actions={
          <NerveButton
            onClick={() => {
              void load();
              void refresh();
              void onRefresh();
            }}
          >
            刷新
          </NerveButton>
        }
      />
      <div className="cr-stats-row" style={{ marginBottom: 16 }}>
        <div className="stat-pill stat-blue">
          <div className="stat-pill-val">{pack || health?.pack || "—"}</div>
          <div className="stat-pill-lbl">当前规则包</div>
        </div>
        <div className="stat-pill stat-green">
          <div className="stat-pill-val">{sets.length}</div>
          <div className="stat-pill-lbl">规则集（文件夹）</div>
        </div>
        <div className="stat-pill">
          <div className="stat-pill-val">
            {sets.reduce((n, s) => n + s.rule_count, 0)}
          </div>
          <div className="stat-pill-lbl">YAML 规则</div>
        </div>
      </div>
      <p className="muted small" style={{ marginBottom: 12 }}>
        规则集对应 pack 内 <code>rules/&lt;文件夹&gt;/</code>；规则为其中每个 YAML。
      </p>
      {sets.length === 0 ? (
        <NerveEmpty description="当前包下无规则集目录" />
      ) : (
        <div className="module-grid">
          {sets.map((s) => (
            <div
              key={s.id}
              className={`protection-module-card${s.enabled ? "" : " mod-card-disabled"}`}
            >
              <div className="protection-module-head">
                <div>
                  <div className="cr-set-title">{s.name}</div>
                  <div className="muted small">
                    {s.enabled_count}/{s.rule_count} 启用
                  </div>
                </div>
                <div className="protection-module-head-actions">
                  <NerveSwitch
                    checked={s.enabled}
                    disabled={saving}
                    onChange={(e) => void toggleSet(s.id, e.target.checked)}
                  />
                </div>
              </div>
              <div className="protection-module-actions">
                <NerveButton
                  size="sm"
                  variant="link"
                  onClick={() => setRulesModal({ id: s.id, name: s.name })}
                >
                  查看规则
                </NerveButton>
              </div>
            </div>
          ))}
        </div>
      )}
      <PackRulesModal
        open={!!rulesModal}
        ruleSetId={rulesModal?.id ?? ""}
        ruleSetName={rulesModal?.name ?? ""}
        onClose={() => setRulesModal(null)}
        onChanged={() => void refresh()}
      />
    </div>
  );
}

export function LevelPage(_props: SharedProps) {
  const { overlay, setOverlay, save, error, saving } = useOverlay();
  if (!overlay) return <p className="muted">加载中…</p>;
  return (
    <div>
      <NervePageHeader
        title="防护粒度"
        actions={
          <NerveButton
            variant="primary"
            disabled={saving}
            onClick={() => void save(overlay)}
          >
            保存
          </NerveButton>
        }
      />
      {error ? <NerveAlert tone="error">{error}</NerveAlert> : null}
      <NerveCard title="全局强度">
        <NerveFormItem label="检测档">
          <NerveSelect
            value={String(overlay.level)}
            options={[
              { value: "low", label: "宽松 (low)" },
              { value: "medium", label: "中等 (medium)" },
              { value: "high", label: "严格 (high)" },
            ]}
            onChange={(e) => setOverlay({ ...overlay, level: e.target.value })}
          />
        </NerveFormItem>
        <NerveFormItem label="仅观察（不拦截）">
          <NerveSwitch
            checked={!!overlay.observe_only}
            onChange={(e) =>
              setOverlay({ ...overlay, observe_only: e.target.checked })
            }
          />
        </NerveFormItem>
        <NerveFormItem label="禁用分类（逗号分隔）">
          <NerveInput
            wide
            value={overlay.disabled_categories.join(",")}
            onChange={(e) =>
              setOverlay({
                ...overlay,
                disabled_categories: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
            placeholder="如 sqli, xss"
          />
        </NerveFormItem>
      </NerveCard>
    </div>
  );
}

export function SemanticPage({ health, onRefresh }: SharedProps) {
  const { overlay, setOverlay, save, error, saving, load } = useOverlay();
  if (!overlay) return <p className="muted">加载中…</p>;

  const packOn = health?.semantic_enabled ?? false;
  const overlayOn = overlay.semantic_enabled !== false;
  const effectiveTrial = packOn && overlayOn;

  return (
    <div>
      <NervePageHeader
        title="语义"
        subtitle="pack 策略只读 + 试打 overlay 粗开关"
        actions={
          <div className="bench-actions">
            <NerveButton
              onClick={() => {
                void load();
                void onRefresh();
              }}
            >
              刷新
            </NerveButton>
            <NerveButton
              variant="primary"
              disabled={saving}
              onClick={() => void save(overlay)}
            >
              保存 overlay
            </NerveButton>
          </div>
        }
      />
      {error ? <NerveAlert tone="error">{error}</NerveAlert> : null}

      <NerveAlert tone="info" style={{ marginBottom: 16 }}>
        下方「pack 策略」来自 <code>/api/health</code>（引擎真实配置）。Overlay
        开关只影响 Dashboard <strong>试打</strong>路径的命中后处理（清零语义分 /
        信号）；WAF 嵌入热路径仍以 pack 为准。
      </NerveAlert>

      <div className="expert-stat-grid" style={{ marginBottom: 16 }}>
        <NerveCard title="pack · semantic_enabled">
          <div className="expert-stat">
            <NerveTag tone={packOn ? "green" : "red"}>
              {packOn ? "启用" : "关闭"}
            </NerveTag>
            <div className="muted small">
              signatures={health?.semantic_signature_count ?? 0}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="语义包">
          <div className="expert-stat">
            <strong className="small">
              {health?.semantic_pack_version || "内置 / 未声明"}
            </strong>
            <div className="muted small break-all">
              {health?.semantic_pack_path || "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="Signals">
          <div className="expert-stat">
            <NerveTag tone={health?.signals_enabled ? "green" : "red"}>
              {health?.signals_enabled ? "启用" : "关闭"}
            </NerveTag>
            <div className="muted small">
              feature={health?.signals_feature_count ?? 0} · fingerprint=
              {health?.signals_fingerprint_count ?? 0}
            </div>
            <div className="muted small break-all">
              {health?.signals_pack_path || "—"} · v=
              {health?.signals_pack_version || "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="试打生效">
          <div className="expert-stat">
            <NerveTag tone={effectiveTrial ? "green" : "red"}>
              {effectiveTrial ? "语义分可计入" : "语义分将被剥离"}
            </NerveTag>
            <div className="muted small">
              pack={String(packOn)} ∧ overlay={String(overlayOn)}
            </div>
          </div>
        </NerveCard>
      </div>

      <NerveCard title="试打 overlay（粗粒度）">
        <NerveFormItem label="启用语义（试打）">
          <NerveSwitch
            checked={overlay.semantic_enabled !== false}
            onChange={(e) =>
              setOverlay({ ...overlay, semantic_enabled: e.target.checked })
            }
          />
        </NerveFormItem>
        <p className="muted small">
          细粒度语义签名由规则包提供，不可在此编辑。关闭本开关后，试打结果会去掉
          semantic_score / semantic_signals，不改引擎内部策略。
        </p>
      </NerveCard>
    </div>
  );
}

export function AlgorithmPage({ health, onRefresh }: SharedProps) {
  const { overlay, setOverlay, save, error, saving, load } = useOverlay();
  if (!overlay) return <p className="muted">加载中…</p>;

  const packOn = health?.adaptive_enabled ?? false;
  const overlayOn = overlay.adaptive_enabled !== false;
  const effectiveTrial = packOn && overlayOn;

  return (
    <div>
      <NervePageHeader
        title="算法"
        subtitle="自适应 / L3 · pack 策略 + 试打 overlay"
        actions={
          <div className="bench-actions">
            <NerveButton
              onClick={() => {
                void load();
                void onRefresh();
              }}
            >
              刷新
            </NerveButton>
            <NerveButton
              variant="primary"
              disabled={saving}
              onClick={() => void save(overlay)}
            >
              保存 overlay
            </NerveButton>
          </div>
        }
      />
      {error ? <NerveAlert tone="error">{error}</NerveAlert> : null}

      <NerveAlert tone="info" style={{ marginBottom: 16 }}>
        pack 侧 <code>adaptive_*</code> / <code>model_version</code> /
        阈值档 / <code>inspect_mode</code> 为引擎真实策略。Overlay
        自适应开关仅影响试打命中后的 model 分剥离。
      </NerveAlert>

      <div className="expert-stat-grid" style={{ marginBottom: 16 }}>
        <NerveCard title="pack · adaptive">
          <div className="expert-stat">
            <NerveTag tone={packOn ? "green" : "red"}>
              {packOn ? "启用" : "关闭"}
            </NerveTag>
            <div className="muted small">
              contribute=
              {String(health?.adaptive_contribute ?? false)}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="model_version">
          <div className="expert-stat">
            <strong>{health?.model_version || "—"}</strong>
            <div className="muted small">内置 / pack 声明版本</div>
          </div>
        </NerveCard>
        <NerveCard title="inspect_mode">
          <div className="expert-stat">
            <strong>{health?.inspect_mode ?? "—"}</strong>
            <div className="muted small">
              max={health?.max_inspect_ms ?? "—"}ms · fast_max=
              {health?.fast_max_inspect_ms ?? "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="阈值三档">
          <div className="expert-stat">
            <strong>
              {health?.threshold_low ?? "—"}/
              {health?.threshold_medium ?? health?.block_threshold ?? "—"}/
              {health?.threshold_high ?? "—"}
            </strong>
            <div className="muted small">low / medium / high block_threshold</div>
          </div>
        </NerveCard>
        <NerveCard title="流水线">
          <div className="expert-stat">
            <div className="muted small">
              decode={String(health?.pipeline_decode ?? "—")} · structural=
              {String(health?.pipeline_structural ?? "—")} · base64=
              {String(health?.pipeline_base64 ?? "—")}
            </div>
            <div className="muted small">accel={health?.accel ?? "—"}</div>
          </div>
        </NerveCard>
        <NerveCard title="试打生效">
          <div className="expert-stat">
            <NerveTag tone={effectiveTrial ? "green" : "red"}>
              {effectiveTrial ? "模型分可计入" : "模型分将被剥离"}
            </NerveTag>
            <div className="muted small">
              pack={String(packOn)} ∧ overlay={String(overlayOn)}
            </div>
          </div>
        </NerveCard>
      </div>

      <NerveCard title="试打 overlay（粗粒度）">
        <NerveFormItem label="启用自适应（试打）">
          <NerveSwitch
            checked={overlay.adaptive_enabled !== false}
            onChange={(e) =>
              setOverlay({ ...overlay, adaptive_enabled: e.target.checked })
            }
          />
        </NerveFormItem>
        <p className="muted small">
          模型特征与 contribute 由 pack / 引擎决定，Dashboard
          不开放细配。关闭本开关后，试打结果会去掉 model_score / model 字段。
        </p>
      </NerveCard>
    </div>
  );
}

function defaultAdmission(): AdmissionConfig {
  return {
    ddos: {
      enabled: true,
      action: "block",
      global: { enabled: true, requests_per_second: 2000, burst: 4000 },
      ip: {
        enabled: true,
        requests_per_second: 50,
        burst: 100,
        window_sec: 10,
        window_max_requests: 200,
        block_duration_sec: 600,
      },
      subnet: {
        enabled: true,
        prefix_v4: 24,
        requests_per_second: 500,
        window_sec: 10,
      },
      concurrency: { enabled: true, max_concurrent_per_ip: 64 },
      burst: {
        enabled: true,
        spike_factor: 5,
        min_samples: 20,
        ewma_alpha: 0.05,
      },
      blocklist: { enabled: true, max_entries: 100000 },
      kernel_drop: {
        enabled: false,
        iface: "eth0",
        min_score: 70,
        dedup_ttl_sec: 60,
        source: "nerve-ddos",
      },
    },
    cc: {
      enabled: true,
      requests_per_minute: 120,
      burst: 40,
      block_duration_sec: 300,
      action: "challenge",
    },
    bot: { enabled: true, action: "challenge", score_threshold: 50 },
    geo: {
      enabled: false,
      block_countries: [],
      allow_countries: [],
      action: "block",
      ip_country_overrides: [],
    },
  };
}

export function AdmissionPage(_props: SharedProps) {
  
  const [cfg, setCfg] = useState<AdmissionConfig | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void api
      .admission()
      .then(setCfg)
      .catch((e: unknown) => nerveToast(e instanceof Error ? e.message : String(e), false));
  }, []);

  const save = async () => {
    if (!cfg) return;
    setSaving(true);
    try {
      setCfg(await api.putAdmission(cfg));
      nerveToast("已保存");
    } catch (e) {
      nerveToast(e instanceof Error ? e.message : String(e), false);
    } finally {
      setSaving(false);
    }
  };

  const c = cfg ?? defaultAdmission();

  return (
    <div>
      <NervePageHeader
        title="准入防护"
        actions={
          <NerveButton variant="primary" disabled={saving} onClick={() => void save()}>
            保存
          </NerveButton>
        }
      />
      <div className="expert-stat-grid">
        <NerveCard title="DDoS / 洪泛防护">
          <NerveFormItem label="启用">
            <NerveSwitch
              checked={c.ddos.enabled}
              onChange={(e) =>
                setCfg({ ...c, ddos: { ...c.ddos, enabled: e.target.checked } })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="单 IP 每秒请求">
            <NerveInput
              value={String(c.ddos.ip.requests_per_second)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    ip: {
                      ...c.ddos.ip,
                      requests_per_second: Number(e.target.value) || 0,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="单 IP 突发">
            <NerveInput
              value={String(c.ddos.ip.burst)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    ip: { ...c.ddos.ip, burst: Number(e.target.value) || 0 },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="全站 QPS 上限">
            <NerveInput
              value={String(c.ddos.global.requests_per_second)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    global: {
                      ...c.ddos.global,
                      requests_per_second: Number(e.target.value) || 0,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="子网 /24 RPS">
            <NerveInput
              value={String(c.ddos.subnet.requests_per_second)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    subnet: {
                      ...c.ddos.subnet,
                      requests_per_second: Number(e.target.value) || 0,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="单 IP 最大并发">
            <NerveInput
              value={String(c.ddos.concurrency.max_concurrent_per_ip)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    concurrency: {
                      ...c.ddos.concurrency,
                      max_concurrent_per_ip: Number(e.target.value) || 0,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="动作">
            <NerveSelect
              value={c.ddos.action}
              options={[
                { value: "block", label: "拦截" },
                { value: "challenge", label: "挑战" },
                { value: "observe", label: "观察" },
              ]}
              onChange={(e) =>
                setCfg({ ...c, ddos: { ...c.ddos, action: e.target.value } })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="内核丢包 (eBPF)">
            <NerveSwitch
              checked={c.ddos.kernel_drop.enabled}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    kernel_drop: {
                      ...c.ddos.kernel_drop,
                      enabled: e.target.checked,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="网卡 (TC attach)">
            <NerveInput
              value={c.ddos.kernel_drop.iface}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    kernel_drop: {
                      ...c.ddos.kernel_drop,
                      iface: e.target.value,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="内核封禁最低分数">
            <NerveInput
              value={String(c.ddos.kernel_drop.min_score)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  ddos: {
                    ...c.ddos,
                    kernel_drop: {
                      ...c.ddos.kernel_drop,
                      min_score: Number(e.target.value) || 0,
                    },
                  },
                })
              }
            />
          </NerveFormItem>
        </NerveCard>

        <NerveCard title="CC / 限流">
          <NerveFormItem label="启用">
            <NerveSwitch
              checked={c.cc.enabled}
              onChange={(e) =>
                setCfg({ ...c, cc: { ...c.cc, enabled: e.target.checked } })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="每分钟请求数">
            <NerveInput
              value={String(c.cc.requests_per_minute)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  cc: {
                    ...c.cc,
                    requests_per_minute: Number(e.target.value) || 0,
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="突发">
            <NerveInput
              value={String(c.cc.burst)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  cc: { ...c.cc, burst: Number(e.target.value) || 0 },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="动作">
            <NerveSelect
              value={c.cc.action}
              options={[
                { value: "block", label: "拦截" },
                { value: "challenge", label: "挑战" },
                { value: "observe", label: "观察" },
              ]}
              onChange={(e) =>
                setCfg({ ...c, cc: { ...c.cc, action: e.target.value } })
              }
            />
          </NerveFormItem>
        </NerveCard>

        <NerveCard title="Bot">
          <NerveFormItem label="启用">
            <NerveSwitch
              checked={c.bot.enabled}
              onChange={(e) =>
                setCfg({ ...c, bot: { ...c.bot, enabled: e.target.checked } })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="评分阈值">
            <NerveInput
              value={String(c.bot.score_threshold)}
              onChange={(e) =>
                setCfg({
                  ...c,
                  bot: {
                    ...c.bot,
                    score_threshold: Number(e.target.value) || 0,
                  },
                })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="动作">
            <NerveSelect
              value={c.bot.action}
              options={[
                { value: "block", label: "拦截" },
                { value: "challenge", label: "挑战" },
                { value: "observe", label: "观察" },
              ]}
              onChange={(e) =>
                setCfg({ ...c, bot: { ...c.bot, action: e.target.value } })
              }
            />
          </NerveFormItem>
        </NerveCard>

        <NerveCard title="Geo">
          <NerveFormItem label="启用">
            <NerveSwitch
              checked={c.geo.enabled}
              onChange={(e) =>
                setCfg({ ...c, geo: { ...c.geo, enabled: e.target.checked } })
              }
            />
          </NerveFormItem>
          <NerveFormItem label="封禁国家（逗号分隔）">
            <NerveInput
              wide
              value={c.geo.block_countries.join(",")}
              onChange={(e) =>
                setCfg({
                  ...c,
                  geo: {
                    ...c.geo,
                    block_countries: e.target.value
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  },
                })
              }
              placeholder="CN,US"
            />
          </NerveFormItem>
          <NerveFormItem label="IP→国家覆盖（演示，一行 ip,CC）">
            <NerveInput
              wide
              value={c.geo.ip_country_overrides
                .map((o) => `${o.ip},${o.country}`)
                .join(";")}
              onChange={(e) =>
                setCfg({
                  ...c,
                  geo: {
                    ...c.geo,
                    ip_country_overrides: e.target.value
                      .split(";")
                      .map((line) => line.trim())
                      .filter(Boolean)
                      .map((line) => {
                        const [ip, country] = line.split(",").map((s) => s.trim());
                        return { ip: ip || "", country: country || "" };
                      })
                      .filter((o) => o.ip && o.country),
                  },
                })
              }
              placeholder="1.2.3.4,CN;5.6.7.8,US"
            />
          </NerveFormItem>
        </NerveCard>
      </div>
    </div>
  );
}
