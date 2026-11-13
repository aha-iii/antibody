import { StrictMode, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  NerveAlert,
  NerveButton,
  NerveCard,
  NerveEmpty,
  NerveForm,
  NerveFormItem,
  NerveInput,
  NerveModal,
  NervePageHeader,
  NervePagination,
  NerveSearchInput,
  NerveSectionCard,
  NerveSelect,
  NerveSwitch,
  NerveTable,
  NerveTableActions,
  NerveTableToolbar,
  NerveTag,
  NerveTabBar,
  NerveTextarea,
  defaultPaginationState,
  nerveConfirm,
  nerveResult,
  paginate,
  NERVE_COL_ACTIONS,
} from "@nerve/ui";

function App() {
  const [tab, setTab] = useState("form");
  const [name, setName] = useState("");
  const [level, setLevel] = useState("medium");
  const [on, setOn] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [pageState, setPageState] = useState(defaultPaginationState());

  const rows = useMemo(
    () =>
      Array.from({ length: 23 }, (_, i) => ({
        id: `r-${i + 1}`,
        name: `规则集 ${i + 1}`,
        status: i % 3 === 0 ? "停用" : "可用",
      })),
    [],
  );
  const pageRows = paginate(rows, pageState.page, pageState.pageSize);

  return (
    <div style={{ maxWidth: 960, margin: "24px auto", padding: "0 16px" }}>
      <NervePageHeader
        title="Nerve UI Playground"
        subtitle="独立组件库演示 · 原 Console 未改动"
        actions={
          <NerveButton
            variant="primary"
            onClick={() =>
              void nerveResult({ type: "success", title: "Hello", message: "@nerve/ui 已就绪" })
            }
          >
            试一下 Result
          </NerveButton>
        }
      />

      <NerveTabBar
        tabs={[
          { id: "form", label: "表单" },
          { id: "table", label: "表格" },
          { id: "empty", label: "空状态" },
        ]}
        activeId={tab}
        onChange={setTab}
      />

      {tab === "form" ? (
        <NerveCard title="nerve-form 示例" tip="样式来自原 Console">
          <NerveForm>
            <NerveFormItem label="名称">
              <NerveInput
                wide
                value={name}
                placeholder="请输入"
                onChange={(e) => setName(e.target.value)}
              />
            </NerveFormItem>
            <NerveFormItem label="强度">
              <NerveSelect
                value={level}
                options={[
                  { value: "low", label: "低 · 更少误报" },
                  { value: "medium", label: "中 · 推荐" },
                  { value: "high", label: "高 · 更严" },
                ]}
                onChange={(e) => setLevel(e.target.value)}
              />
            </NerveFormItem>
            <NerveFormItem label="说明">
              <NerveTextarea rows={3} placeholder="可选" />
            </NerveFormItem>
            <NerveFormItem label="启用">
              <NerveSwitch checked={on} onChange={(e) => setOn(e.target.checked)} />
            </NerveFormItem>
            <div style={{ display: "flex", gap: 8 }}>
              <NerveButton variant="primary" onClick={() => setModalOpen(true)}>
                打开 Modal
              </NerveButton>
              <NerveButton
                onClick={() =>
                  void nerveConfirm({
                    title: "确认同步",
                    message: "将用策略库最新配置覆盖本应用？",
                  }).then((ok) => {
                    if (ok) void nerveResult({ type: "success", title: "已确认" });
                  })
                }
              >
                Confirm
              </NerveButton>
              <NerveTag tone="blue">内置</NerveTag>
              <NerveTag tone="green">可用</NerveTag>
            </div>
          </NerveForm>
        </NerveCard>
      ) : null}

      {tab === "table" ? (
        <NerveSectionCard title="nerve-table" count={rows.length}>
          <NerveTableToolbar>
            <NerveSearchInput placeholder="搜索规则集" />
            <NerveButton size="sm" variant="primary">
              添加
            </NerveButton>
          </NerveTableToolbar>
          <NerveTable
            rowKey="id"
            columns={[
              { key: "name", title: "规则集", dataIndex: "name" },
              {
                key: "status",
                title: "状态",
                render: (r) => (
                  <NerveTag tone={r.status === "可用" ? "green" : "orange"}>{r.status}</NerveTag>
                ),
              },
              {
                key: "ops",
                title: "操作",
                className: NERVE_COL_ACTIONS,
                render: (r) => (
                  <NerveTableActions
                    actions={[
                      { key: "view", label: "查看", primary: true },
                      { key: "rm", label: "移除", danger: true, onClick: () => console.log(r.id) },
                    ]}
                  />
                ),
              },
            ]}
            dataSource={pageRows}
          />
          <NervePagination
            total={rows.length}
            page={pageState.page}
            pageSize={pageState.pageSize}
            onChange={setPageState}
          />
        </NerveSectionCard>
      ) : null}

      {tab === "empty" ? (
        <>
          <NerveAlert tone="info">空状态带图标，与原 Console emptyState 一致。</NerveAlert>
          <NerveEmpty
            description="暂无自定义规则集"
            hint="可在「防护策略」挂载后，点内置策略卡片上的同步图标写入本应用。"
          />
        </>
      ) : null}

      <NerveModal
        open={modalOpen}
        title="示例弹窗"
        onClose={() => setModalOpen(false)}
        footer={
          <>
            <NerveButton onClick={() => setModalOpen(false)}>取消</NerveButton>
            <NerveButton variant="primary" onClick={() => setModalOpen(false)}>
              保存
            </NerveButton>
          </>
        }
      >
        <p>名称：{name || "（空）"} · 强度：{level}</p>
      </NerveModal>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
