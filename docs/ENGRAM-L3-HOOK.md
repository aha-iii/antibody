# Engram / L3 外部智能接入（占位）

> 状态：接口预留；**不**开放裸模型 hard-block。

## 原则

- L3（adaptive / Engram）只 **加分 / 佐证 Fusion**，不能单独 `block`
- 生产默认：启发式或 Linear JSON；ONNX / Engram 先走 **shadow 对比**
- 平台 Intelligent 柱输出应落入：
  1. 声明式 `feature`（经可信内部头或 signals 注入），或
  2. `adaptive::FeatureSnapshot` 扩展维，再进 Fusion

## 推荐接入顺序

1. Shadow：Engram 分数与 L1 命中并行记录，不对流量生效
2. `contribute=true`：仅当 L1/L2/关键字已有信号时参与 challenge/block
3. Console 展示 `model` / Engram 证据，运维可关闭

## 环境变量（现有）

| 变量 | 作用 |
|------|------|
| pack `[policy.adaptive].enabled` | 开关 L3 |
| `contribute` | 是否写入 Fusion |
| `model_path` | Linear/ONNX 模型路径 |

Engram 远端 URL / SDK **尚未**接入本仓库；落地时在 `nerve-antibody-adaptive` 增加 backend，勿改 L1 热路径。
