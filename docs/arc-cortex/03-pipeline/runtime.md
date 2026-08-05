# nerve-antibody-runtime

**Evaluator** 执行器：Arc/Cortex 路由与融合。

## 核心类型

- `Evaluator` — 绑定一档 `Program`
- `InspectPlan` — 单次 inspect 规划（path · inline_fast_lane · api_positive_lane）
- `NativeHit` — 融合结果（含 `inspect_path`: `fast`|`deep`）

## 子模块

| 模块 | 职责 |
|------|------|
| `eval` | `plan_inspect` · `inspect_plan` · 融合 |
| `route_gate` | Stage-0：Arc vs Cortex · 线性分 · fast_lanes |
| `types` | `NativeRequest` · `NativeHit` |
| `parallel` | Deep tail 并行框架（feature `parallel-deep`） |

## Arc-Cortex 路由

```text
plan_inspect → resolve_inspect_path (auto/deep/fast)
  → Arc：for_fast_path · 可选 inline_fast_lane
  → Cortex：lazy/full decode · L2 · L3
```

`route_gate` 读 pack policy + `signals.yaml` hints。

## 模式

| `NERVE_NATIVE_INSPECT_MODE` | 行为 |
|-----------------------------|------|
| `auto` | route_gate 选 Arc/Cortex |
| `fast` | 强制 Arc |
| `deep` | 强制 Cortex（bench 常用） |
