# 03 · 检测流水线（Domain / Engine 核心）

Arc-Cortex **裁决算法**所在层：decode → 匹配 → 语义 → 自适应 → 融合。

| Crate | 文档 | Arc / Cortex |
|-------|------|--------------|
| `nerve-antibody-pipeline` | [pipeline.md](./pipeline.md) | 视图构建；Cortex 全量 decode |
| `nerve-antibody-accel` | [accel.md](./accel.md) | Aho / Hyperscan 多模加速 |
| `nerve-antibody-semantic` | [semantic.md](./semantic.md) | L2 ·  mainly Cortex |
| `nerve-antibody-adaptive` | [adaptive.md](./adaptive.md) | L3 · Cortex only |
| `nerve-antibody-runtime` | [runtime.md](./runtime.md) | **Evaluator** · route_gate → Arc/Cortex |

## L1–L3 与路径

| 层 | 模块 | 单独拦截 | Arc | Cortex |
|----|------|----------|-----|--------|
| L1 | runtime 规则 + allow | 能 | ✓ 主路径 | ✓ 全量 |
| L2 | semantic | 否 | ✗ | ✓ |
| L3 | adaptive | 否 | ✗ | ✓ |
