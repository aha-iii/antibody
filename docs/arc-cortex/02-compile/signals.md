# nerve-antibody-signals

请求级 **feature**（布尔/数值）与 **fingerprint**（路径/业务类）。

## 职责

- 供 L1 规则 `feature` / `fingerprint` / `length_*` 谓词
- 供 `route_gate` Arc/Cortex 路由（`signals.yaml` 的 fast_hints / deep_hints）
- 内置 Rust 信号 + pack 声明扩展（`SignalPack`）

## 主要 API

- `compute_signals_with_pack()` — Engine / Runtime 热路径
- `load_signal_pack()` — 从 pack 加载 YAML

## 配置

baseline 包：[`packs/baseline/signals/signals.yaml`](../../../packs/baseline/signals/signals.yaml)。
