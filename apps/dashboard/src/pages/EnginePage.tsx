import { useEffect, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NervePageHeader,
  NervePagination,
  NerveTag,
  NerveTable,
  defaultPaginationState,
  paginate,
  type NervePaginationState,
  type NerveTableColumn,
} from "@nerve/ui";
import type { Health, PackInfo } from "../api";

type PackRow = PackInfo & Record<string, unknown>;

const PACK_COLUMNS: NerveTableColumn<PackRow>[] = [
  { key: "id", title: "包 ID", dataIndex: "id" },
  {
    key: "current",
    title: "状态",
    render: (row) =>
      row.current ? <NerveTag tone="blue">当前</NerveTag> : <span className="muted">—</span>,
  },
  { key: "path", title: "路径", dataIndex: "path" },
];

type Props = {
  health: Health | null;
  packs: PackInfo[];
  bootError: string | null;
  onRefresh: () => Promise<void>;
};

export function EnginePage({ health, packs, bootError, onRefresh }: Props) {
  const [pagination, setPagination] = useState<NervePaginationState>(
    defaultPaginationState(),
  );
  const rows: PackRow[] = packs.map((p) => ({ ...p }));
  const pageRows = paginate(rows, pagination.page, pagination.pageSize);

  useEffect(() => {
    setPagination((p) => ({ ...p, page: 1 }));
  }, [packs]);

  return (
    <div>
      <NervePageHeader
        title="引擎状态"
        subtitle="当前加载规则包与健康快照"
        actions={
          <NerveButton onClick={() => void onRefresh()}>刷新</NerveButton>
        }
      />

      {bootError ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {bootError}
        </NerveAlert>
      ) : null}

      <div className="expert-stat-grid">
        <NerveCard title="就绪">
          {health ? (
            <div className="expert-stat">
              <NerveTag tone={health.ready ? "green" : "red"}>
                {health.ready ? "READY" : "DOWN"}
              </NerveTag>
            </div>
          ) : (
            <NerveEmpty description="未连接" sm />
          )}
        </NerveCard>
        <NerveCard title="规则包">
          <div className="expert-stat">
            <div>
              <strong>{health?.pack ?? "—"}</strong>
            </div>
            <div className="muted small">
              id={health?.pack_id ?? "—"} · v={health?.pack_version ?? "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="规则数">
          <div className="expert-stat">
            <strong className="expert-stat-num">{health?.rule_count ?? "—"}</strong>
            <div className="muted small">
              L/M/H={health?.rules_low ?? "—"}/{health?.rules_medium ?? "—"}/
              {health?.rules_high ?? "—"}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="拦截阈值">
          <div className="expert-stat">
            <strong className="expert-stat-num">
              {health?.threshold_low ?? "—"}/{health?.threshold_medium ?? health?.block_threshold ?? "—"}/
              {health?.threshold_high ?? "—"}
            </strong>
            <div className="muted small">
              low/medium/high · observe_only={String(health?.observe_only ?? false)}
            </div>
            <div className="muted small">
              semantic={String(health?.semantic_enabled ?? false)} · adaptive=
              {String(health?.adaptive_enabled ?? false)}
              {health?.adaptive_contribute ? "+contribute" : ""}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="加速 / 模式">
          <div className="expert-stat">
            <code>{health?.accel ?? "—"}</code>
            <div className="muted small">
              inspect_mode={health?.inspect_mode ?? "—"} · max=
              {health?.max_inspect_ms ?? "—"}ms
            </div>
          </div>
        </NerveCard>
        <NerveCard title="模型 / Signals">
          <div className="expert-stat">
            <strong>{health?.model_version || "—"}</strong>
            <div className="muted small">
              signals={health?.signals_enabled ? "on" : "off"} · f=
              {health?.signals_feature_count ?? 0} · fp=
              {health?.signals_fingerprint_count ?? 0} · semantic_sig=
              {health?.semantic_signature_count ?? 0}
            </div>
          </div>
        </NerveCard>
        <NerveCard title="内容哈希">
          <div className="expert-stat">
            <code className="small break-all">{health?.content_hash ?? "—"}</code>
          </div>
        </NerveCard>
      </div>

      <NerveCard title="可用规则包" tip={health?.packs_root} style={{ marginTop: 16 }}>
        <NerveTable
          columns={PACK_COLUMNS}
          dataSource={pageRows}
          rowKey="id"
          emptyText="未扫描到 pack.toml"
        />
        <NervePagination
          total={rows.length}
          page={pagination.page}
          pageSize={pagination.pageSize}
          onChange={setPagination}
        />
      </NerveCard>
    </div>
  );
}
