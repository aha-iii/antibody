import { useCallback, useEffect, useState } from "react";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveInput,
  NerveModal,
  NervePageHeader,
  NervePagination,
  NerveSelect,
  NerveTable,
  NerveTableToolbar,
  NerveTag,
  defaultPaginationState,
  paginate,
  type NervePaginationState,
  type NerveTableColumn,
  type NerveTagTone,
} from "@nerve/ui";
import {
  api,
  type Health,
  type PackInfo,
  type SampleCase,
} from "../api";
import { InspectWorkbench } from "./InspectWorkbench";

type Row = SampleCase & Record<string, unknown>;

function expectTone(a: string): NerveTagTone {
  if (a === "block") return "red";
  if (a === "observe") return "orange";
  if (a === "pass") return "green";
  return "default";
}

type Props = {
  health: Health | null;
  packs: PackInfo[];
  onHealth: (h: Health) => void;
  onPacksRefresh: () => Promise<void>;
};

export function SamplesPage({
  health,
  packs,
  onHealth,
  onPacksRefresh,
}: Props) {
  const [category, setCategory] = useState("");
  const [q, setQ] = useState("");
  const [categories, setCategories] = useState<string[]>([]);
  const [samples, setSamples] = useState<SampleCase[]>([]);
  const [pack, setPack] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState<NervePaginationState>(
    defaultPaginationState(),
  );

  const [modalOpen, setModalOpen] = useState(false);
  const [modalSample, setModalSample] = useState<SampleCase | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const prefer = health?.pack || "baseline";
      let out = await api.samples({
        pack: prefer,
        category: category || undefined,
        q: q || undefined,
      });
      if (out.count === 0 && prefer !== "baseline") {
        out = await api.samples({
          pack: "baseline",
          category: category || undefined,
          q: q || undefined,
        });
      }
      setSamples(out.samples);
      setCategories(out.categories);
      setPack(out.pack);
      setPagination((p) => ({ ...p, page: 1 }));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [health?.pack, category, q]);

  useEffect(() => {
    void load();
  }, [load]);

  const openDetect = (sample: SampleCase) => {
    setModalSample(sample);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setModalSample(null);
  };

  const columns: NerveTableColumn<Row>[] = [
    {
      key: "rule",
      title: "规则 / 案例",
      render: (row) => (
        <div>
          <div>
            <code>{row.rule_id || "(clean)"}</code>
          </div>
          <div className="muted small">{row.name}</div>
          <div className="muted small">{row.id}</div>
        </div>
      ),
    },
    { key: "category", title: "分类", dataIndex: "category" },
    {
      key: "expect",
      title: "期望",
      render: (row) => (
        <NerveTag tone={expectTone(String(row.expect_action))}>
          {row.expect_action}
        </NerveTag>
      ),
    },
    {
      key: "level",
      title: "档位",
      render: (row) => <span className="small">{row.min_level}</span>,
    },
    {
      key: "req",
      title: "请求摘要",
      render: (row) => {
        const r = row.request;
        const qpart = r.query ? `?${r.query}` : "";
        return (
          <code className="small">
            {r.method} {r.uri}
            {qpart.length > 48 ? `${qpart.slice(0, 48)}…` : qpart}
          </code>
        );
      },
    },
    {
      key: "run",
      title: "操作",
      render: (row) => (
        <NerveButton
          size="sm"
          variant="primary"
          onClick={() => openDetect(row)}
        >
          检测
        </NerveButton>
      ),
    },
  ];

  const rows: Row[] = samples.map((s) => ({ ...s }));
  const pageRows = paginate(rows, pagination.page, pagination.pageSize);

  return (
    <div>
      <NervePageHeader
        title="案例库"
        subtitle={`来源 packs/${pack || "…"}/samples · 与规则一一对应`}
        actions={
          <NerveTableToolbar>
            <NerveSelect
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              options={[
                { value: "", label: "全部分类" },
                ...categories.map((c) => ({ value: c, label: c })),
              ]}
            />
            <NerveInput
              placeholder="搜索 rule_id / 名称"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{ width: 220 }}
            />
            <NerveButton onClick={() => void load()} disabled={loading}>
              {loading ? "加载中…" : "刷新"}
            </NerveButton>
          </NerveTableToolbar>
        }
      />

      {error ? (
        <NerveAlert tone="error" style={{ marginBottom: 16 }}>
          {error}
        </NerveAlert>
      ) : null}

      {!loading && samples.length === 0 ? (
        <NerveCard title="无案例">
          <NerveEmpty
            description="当前包没有 samples/"
            hint="请切换到 baseline，或运行 python3 scripts/gen_baseline_samples.py"
          />
        </NerveCard>
      ) : (
        <NerveCard title={`案例列表 (${samples.length})`} tip={pack}>
          <NerveTable
            columns={columns}
            dataSource={pageRows}
            rowKey="id"
            emptyText="无匹配案例"
          />
          <NervePagination
            total={samples.length}
            page={pagination.page}
            pageSize={pagination.pageSize}
            onChange={setPagination}
          />
        </NerveCard>
      )}

      <NerveModal
        open={modalOpen}
        xl
        title={
          modalSample
            ? `检测 · ${modalSample.rule_id || modalSample.id}`
            : "检测"
        }
        onClose={closeModal}
        footer={<NerveButton onClick={closeModal}>关闭</NerveButton>}
      >
        {modalSample ? (
          <InspectWorkbench
            key={modalSample.id}
            health={health}
            packs={packs}
            onHealth={onHealth}
            onPacksRefresh={onPacksRefresh}
            sample={modalSample}
            autoInspect
          />
        ) : null}
      </NerveModal>
    </div>
  );
}
