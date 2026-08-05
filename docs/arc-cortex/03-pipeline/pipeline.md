# nerve-antibody-pipeline

引擎级管线（与 DSL 解耦）：decode · 结构化 · 预算。

## 职责

1. **DecodePipeline** — URL/B64/实体解码 → 多视图 [`RequestViews`]
2. **Structural** — form / JSON / multipart / XML 拆参
3. **Budget** — `max_inspect_ms` · `max_regex_evals` 熔断

## 子模块概念

| 区域 | 说明 |
|------|------|
| decode | 标准归一化、lazy_decode（Cortex 逐层） |
| structural | 结构化字段展开 |
| budget | 超时/次数计数，触发 `budget_exhausted` |

## Arc vs Cortex

- **Arc**：`for_fast_path()` — 轻 pipeline，预算 cap（如 80ms）
- **Cortex**：全量 `build_views`，预算 env 封顶（生产常用 300ms）
