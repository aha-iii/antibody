import { useCallback, useEffect, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveFormItem,
  NerveInput,
  NervePageHeader,
  NerveTable,
  NerveTag,
  nerveToast,
  type NerveTableColumn,
} from "@nerve/ui";
import {
  api,
  type Health,
  type VpChannelCheck,
  type VpEntry,
  type VpProbeOut,
  type VpStatus,
} from "../api";

type Props = {
  health: Health | null;
};

type Row = VpEntry & Record<string, unknown>;

function statusTone(status: string): "blue" | "green" | "orange" | "red" | "default" {
  switch (status.toLowerCase()) {
    case "live":
      return "green";
    case "sandbox":
      return "orange";
    case "draft":
      return "blue";
    case "retired":
      return "default";
    default:
      return "red";
  }
}

export function VpPage({ health }: Props) {
  const [items, setItems] = useState<VpEntry[]>([]);
  const [status, setStatus] = useState<VpStatus | null>(null);
  const [channel, setChannel] = useState<VpChannelCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [importPath, setImportPath] = useState("");
  const [probeQuery, setProbeQuery] = useState("q=nerve-vp-probe-demo01");
  const [probe, setProbe] = useState<VpProbeOut | null>(null);
  const [intelCve, setIntelCve] = useState("CVE-2024-MANUAL01");
  const [intelToken, setIntelToken] = useState("nerve-vp-manual-token01");
  const [intelTitle, setIntelTitle] = useState("Manual intel ingest");

  const refresh = useCallback(async () => {
    try {
      const [list, st] = await Promise.all([api.vpList(), api.vpStatus()]);
      setItems(list.items ?? []);
      setStatus(st);
      setError(null);
      try {
        setChannel(await api.vpUpdatesCheck());
      } catch {
        setChannel(null);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      nerveToast(label);
      await refresh();
    } catch (e) {
      nerveToast(e instanceof Error ? e.message : String(e), false);
    } finally {
      setBusy(false);
    }
  };

  const cols: NerveTableColumn<Row>[] = [
    {
      key: "cve_id",
      title: "CVE",
      render: (row) => <code className="cr-id">{String(row.cve_id)}</code>,
    },
    { key: "title", title: "标题", dataIndex: "title" },
    {
      key: "severity",
      title: "严重度",
      render: (row) => <NerveTag tone="red">{String(row.severity)}</NerveTag>,
    },
    {
      key: "status",
      title: "状态",
      render: (row) => (
        <NerveTag tone={statusTone(String(row.status))}>
          {String(row.status)}
        </NerveTag>
      ),
    },
    {
      key: "rule_count",
      title: "规则",
      render: (row) => <span className="mono">{String(row.rule_count)}</span>,
    },
    {
      key: "actions",
      title: "操作",
      render: (row) => {
        const cve = String(row.cve_id);
        const st = String(row.status).toLowerCase();
        return (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {st !== "live" && st !== "retired" ? (
              <NerveButton
                size="sm"
                disabled={busy}
                onClick={() =>
                  void run(`已挂载沙箱 ${cve}`, () => api.vpSandbox(cve))
                }
              >
                沙箱
              </NerveButton>
            ) : null}
            {st !== "live" && st !== "retired" ? (
              <NerveButton
                size="sm"
                variant="primary"
                disabled={busy}
                onClick={() => {
                  if (
                    !window.confirm(
                      `确认将 ${cve} 晋升为 live？规则将合入热路径并 reload。`,
                    )
                  ) {
                    return;
                  }
                  void run(`已晋升 ${cve}`, () => api.vpPromote(cve));
                }}
              >
                晋升
              </NerveButton>
            ) : null}
            {st === "live" ? (
              <NerveButton
                size="sm"
                variant="danger"
                disabled={busy}
                onClick={() => {
                  if (
                    !window.confirm(
                      `确认回滚 ${cve}（retired）并 reload？`,
                    )
                  ) {
                    return;
                  }
                  void run(`已回滚 ${cve}`, () => api.vpRollback(cve));
                }}
              >
                回滚
              </NerveButton>
            ) : null}
          </div>
        );
      },
    },
  ];

  return (
    <div>
      <NervePageHeader
        title="虚拟补丁"
        subtitle="情报/channel → sandbox 自动 · live 仅人工晋升"
      />

      {error ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {error}
        </NerveAlert>
      ) : null}

      <NerveCard title="更新源（channel → sandbox）" style={{ marginBottom: 16 }}>
        <div className="muted small" style={{ display: "grid", gap: 4, marginBottom: 12 }}>
          {channel ? (
            <>
              <div>
                track=<code>{channel.track}</code> · remote{" "}
                <code>{channel.remote_version}</code> · local{" "}
                <code>{channel.local_version || "—"}</code>
                {" · "}
                <NerveTag tone={channel.update_available ? "orange" : "green"}>
                  {channel.update_available ? "有更新" : "已是最新"}
                </NerveTag>
              </div>
              <div>
                源：<code className="small">{channel.channel_url}</code>
              </div>
              {channel.cve_added?.length ? (
                <div>本版 CVE：{channel.cve_added.join(", ")}</div>
              ) : null}
            </>
          ) : (
            <div>未配置更新源（默认 packs/vp-channel-demo 或 NERVE_VP_CHANNEL_URL）</div>
          )}
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <NerveButton
            size="sm"
            disabled={busy}
            onClick={() =>
              void run("已检查更新", async () => {
                setChannel(await api.vpUpdatesCheck());
              })
            }
          >
            检查更新
          </NerveButton>
          <NerveButton
            size="sm"
            variant="primary"
            disabled={busy}
            onClick={() =>
              void run("已拉取并进沙箱（未 promote）", () => api.vpUpdatesFetch())
            }
          >
            拉取 → sandbox
          </NerveButton>
        </div>
      </NerveCard>

      <NerveCard title="引擎 / VP 状态" style={{ marginBottom: 16 }}>
        <div className="muted small" style={{ display: "grid", gap: 4 }}>
          <div>
            pack：{status?.pack ?? health?.pack ?? "—"} · version{" "}
            {status?.pack_version ?? "—"} · rules {status?.rule_count ?? "—"}
          </div>
          <div>
            VP 合计 {status?.vp_total ?? 0} · live {status?.vp_live_count ?? 0}
            {" · "}
            sandbox{" "}
            {status?.sandbox_mounted
              ? status.sandbox_pack_id ?? "mounted"
              : "未挂载"}
          </div>
        </div>
      </NerveCard>

      <NerveCard title="CVE 列表" style={{ marginBottom: 16 }}>
        {items.length === 0 ? (
          <NerveEmpty description="当前 pack 无 virtual-patches；可离线导入 CVE 目录" />
        ) : (
          <NerveTable columns={cols} dataSource={items as Row[]} rowKey="cve_id" />
        )}
        <div style={{ marginTop: 12 }}>
          <NerveButton size="sm" disabled={busy} onClick={() => void refresh()}>
            刷新
          </NerveButton>
        </div>
      </NerveCard>

      <NerveCard title="情报 → sandbox（模板）" style={{ marginBottom: 16 }}>
        <NerveFormItem label="CVE ID">
          <NerveInput
            value={intelCve}
            onChange={(e) => setIntelCve(e.target.value)}
          />
        </NerveFormItem>
        <NerveFormItem label="标题">
          <NerveInput
            value={intelTitle}
            onChange={(e) => setIntelTitle(e.target.value)}
          />
        </NerveFormItem>
        <NerveFormItem label="match_contains（≥8 字符）">
          <NerveInput
            value={intelToken}
            onChange={(e) => setIntelToken(e.target.value)}
          />
        </NerveFormItem>
        <NerveButton
          size="sm"
          variant="primary"
          disabled={busy || !intelCve.trim() || intelToken.trim().length < 8}
          onClick={() =>
            void run("情报已生成 sandbox", () =>
              api.vpIngest({
                cve_id: intelCve.trim(),
                title: intelTitle.trim(),
                match_contains: intelToken.trim(),
                severity: "high",
                source: "dashboard",
              }),
            )
          }
        >
          生成并挂沙箱
        </NerveButton>
      </NerveCard>

      <NerveCard title="离线导入" style={{ marginBottom: 16 }}>
        <NerveFormItem label="源路径（CVE 目录或含 virtual-patches 的根）">
          <NerveInput
            value={importPath}
            onChange={(e) => setImportPath(e.target.value)}
            placeholder="/path/to/CVE-2024-… 或 …/virtual-patches"
          />
        </NerveFormItem>
        <NerveButton
          size="sm"
          variant="primary"
          disabled={busy || !importPath.trim()}
          onClick={() =>
            void run("导入完成", () => api.vpImport(importPath.trim()))
          }
        >
          导入
        </NerveButton>
      </NerveCard>

      <NerveCard title="探测（Demo probe token）">
        <NerveFormItem label="query">
          <NerveInput
            value={probeQuery}
            onChange={(e) => setProbeQuery(e.target.value)}
          />
        </NerveFormItem>
        <NerveButton
          size="sm"
          disabled={busy}
          onClick={() =>
            void run("探测完成", async () => {
              const out = await api.vpProbe(probeQuery);
              setProbe(out);
            })
          }
        >
          探测
        </NerveButton>
        {probe ? (
          <div className="muted small" style={{ marginTop: 12 }}>
            action=<code>{probe.action}</code> · rule=
            <code>{probe.rule_id || "—"}</code> · path=
            <code>{probe.inspect_path || "—"}</code>
            {probe.action === "pass" ? (
              <div style={{ marginTop: 4 }}>
                若期望 block：先晋升 CVE-2024-DEMO01 为 live 再探测。
              </div>
            ) : null}
          </div>
        ) : null}
      </NerveCard>
    </div>
  );
}
