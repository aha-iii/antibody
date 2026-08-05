import { useCallback, useEffect, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveFormItem,
  NerveInput,
  NervePageHeader,
  NerveSelect,
  NerveTable,
  NerveTag,
  nerveToast,
  type NerveTableColumn,
} from "@nerve/ui";
import {
  api,
  type Health,
  type ShadowFeedback,
  type ShadowSample,
} from "../api";

type Props = {
  health: Health | null;
};

type SampleRow = ShadowSample & Record<string, unknown>;
type FeedbackRow = ShadowFeedback & Record<string, unknown>;

export function ShadowPage({ health }: Props) {
  const [samples, setSamples] = useState<ShadowSample[]>([]);
  const [feedback, setFeedback] = useState<ShadowFeedback[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [uri, setUri] = useState("");
  const [label, setLabel] = useState("fp");
  const [note, setNote] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [exportText, setExportText] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [r, f] = await Promise.all([
        api.shadowRecent(),
        api.shadowFeedbackList(),
      ]);
      setSamples(r.samples ?? []);
      setFeedback(f.items ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const submitFeedback = async () => {
    if (!uri.trim()) {
      nerveToast("请填写 URI", false);
      return;
    }
    setBusy(true);
    try {
      await api.shadowFeedback({
        uri: uri.trim(),
        label,
        note: note.trim(),
        rule_id: ruleId.trim() || undefined,
      });
      nerveToast("已标注");
      setNote("");
      await refresh();
    } catch (e) {
      nerveToast(e instanceof Error ? e.message : String(e), false);
    } finally {
      setBusy(false);
    }
  };

  const doExport = async () => {
    setBusy(true);
    try {
      const text = await api.shadowExportRules();
      setExportText(text);
      nerveToast("已导出 allow 草稿");
    } catch (e) {
      nerveToast(e instanceof Error ? e.message : String(e), false);
    } finally {
      setBusy(false);
    }
  };

  const sampleCols: NerveTableColumn<SampleRow>[] = [
    {
      key: "uri",
      title: "URI",
      render: (row) => (
        <button
          type="button"
          className="linkish"
          onClick={() => {
            setUri(String(row.uri));
            setRuleId(String(row.rule_id || ""));
          }}
        >
          <code className="small">{String(row.uri)}</code>
        </button>
      ),
    },
    {
      key: "would_hit",
      title: "would_hit",
      render: (row) => (
        <NerveTag tone={row.would_hit ? "red" : "green"}>
          {String(row.would_hit)}
        </NerveTag>
      ),
    },
    { key: "action", title: "动作", dataIndex: "action" },
    {
      key: "total_score",
      title: "分",
      render: (row) => <span className="mono">{String(row.total_score)}</span>,
    },
    {
      key: "rule_id",
      title: "规则",
      render: (row) => <code className="cr-id">{String(row.rule_id || "—")}</code>,
    },
  ];

  const feedbackCols: NerveTableColumn<FeedbackRow>[] = [
    {
      key: "uri",
      title: "URI",
      render: (row) => <code className="small">{String(row.uri)}</code>,
    },
    {
      key: "label",
      title: "标注",
      render: (row) => <NerveTag tone="blue">{String(row.label)}</NerveTag>,
    },
    {
      key: "matched_rule_id",
      title: "规则",
      render: (row) => (
        <code className="cr-id">{String(row.matched_rule_id || "—")}</code>
      ),
    },
    {
      key: "note",
      title: "备注",
      render: (row) => <span className="muted small">{String(row.note || "")}</span>,
    },
  ];

  return (
    <div>
      <NervePageHeader
        title="误报 / Shadow"
        subtitle="深扫 Shadow 采样 · 人工标注 · 导出 allow 草稿"
        actions={
          <div className="bench-actions">
            <NerveButton onClick={() => void refresh()}>刷新</NerveButton>
            <NerveButton
              variant="primary"
              disabled={busy}
              onClick={() => void doExport()}
            >
              导出 allow 草稿
            </NerveButton>
          </div>
        }
      />

      {error ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {error}
        </NerveAlert>
      ) : null}

      <p className="muted small" style={{ marginBottom: 12 }}>
        pack={health?.pack ?? "—"} · 点击采样 URI 可填入标注表单。标注标签建议：
        <code>fp</code> / <code>false_positive</code> / <code>allow</code> /{" "}
        <code>veto</code>。
      </p>

      <NerveCard title="标注反馈" style={{ marginBottom: 16 }}>
        <div className="expert-row-2">
          <NerveFormItem label="URI">
            <NerveInput
              wide
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              placeholder="/path?q=…"
            />
          </NerveFormItem>
          <NerveFormItem label="标签">
            <NerveSelect
              value={label}
              options={[
                { value: "fp", label: "fp（误报）" },
                { value: "false_positive", label: "false_positive" },
                { value: "allow", label: "allow" },
                { value: "veto", label: "veto" },
              ]}
              onChange={(e) => setLabel(e.target.value)}
            />
          </NerveFormItem>
        </div>
        <div className="expert-row-2">
          <NerveFormItem label="规则 ID（可选）">
            <NerveInput
              wide
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="matched rule_id"
            />
          </NerveFormItem>
          <NerveFormItem label="备注">
            <NerveInput
              wide
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </NerveFormItem>
        </div>
        <NerveButton
          variant="primary"
          disabled={busy}
          onClick={() => void submitFeedback()}
        >
          提交标注
        </NerveButton>
      </NerveCard>

      <NerveCard title="最近 Shadow 采样" style={{ marginBottom: 16 }}>
        {samples.length === 0 ? (
          <NerveEmpty description="暂无采样（快路径 shadow deep 触发后出现）" />
        ) : (
          <NerveTable
            columns={sampleCols}
            dataSource={samples.map((s) => ({ ...s }))}
            rowKey={(row) => `${row.uri}-${row.rule_id}-${row.total_score}`}
          />
        )}
      </NerveCard>

      <NerveCard title="最近标注" style={{ marginBottom: 16 }}>
        {feedback.length === 0 ? (
          <NerveEmpty description="尚无标注" />
        ) : (
          <NerveTable
            columns={feedbackCols}
            dataSource={feedback.map((f) => ({ ...f }))}
            rowKey={(row) => `${row.uri}-${row.created_ms}`}
          />
        )}
      </NerveCard>

      {exportText != null ? (
        <NerveCard title="导出 YAML（allow 草稿）">
          <pre className="shadow-export mono small">{exportText || "(空)"}</pre>
        </NerveCard>
      ) : null}
    </div>
  );
}
