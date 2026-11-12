# pipeline · 检测流水线

**在线检测核心**：decode 请求 → 加速匹配 → 语义/自适应加分 → 融合裁决。`runtime` 是编排中心，其余 crate 提供能力片段。

| Crate | 职责 | Arc / Cortex |
|-------|------|--------------|
| **`nerve-antibody-pipeline`** | 多轮 decode（url/base64/recursive）、XML/结构解析、字段视图构建、sidechannel 提取、decode 预算 | Cortex 全量 decode；Arc 轻量视图 |
| **`nerve-antibody-accel`** | 多模串匹配后端：默认 `aho-corasick`；feature `accel-hyperscan` 走 Hyperscan FFI | 两者均用 |
| **`nerve-antibody-semantic`** | **L2** 语义：SQLi/XSS/Path 等启发式签名，对 L1 命中加分或 veto |  mainly Cortex |
| **`nerve-antibody-adaptive`** | **L3** 自适应：浅特征、Engram hook，仅加分，**不可单独 block** | Cortex only |
| **`nerve-antibody-runtime`** | **Evaluator**：`route_gate` 选 Arc/Cortex、`plan_inspect`、`inspect_plan`、L1 规则匹配与分数融合 | 路由中枢 |

```text
NativeRequest
  → route_gate (Arc | Cortex)
  → pipeline 构建视图 + decode
  → accel 预过滤 + Program 规则匹配
  → semantic / adaptive 加分
  → NativeHit（verdict + score + inspect_path）
```

文档：[`docs/arc-cortex/03-pipeline/`](../../../docs/arc-cortex/03-pipeline/)
