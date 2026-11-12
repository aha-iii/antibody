# Arc-Cortex 治理架构：沙箱 · 正负检测 · 信号量

> 本文是可公开的结论摘要；设计原文为内部文档，未随仓库发布。  
> 实现：`nerve-antibody-runtime`（拦截信号量）· `nerve-antibody-engine`（沙箱槽 / Shadow）

## 一句话

热路径 = **正负计分 + 三层信号量判决**；旁路 = **沙箱/Shadow 观察 + 人工晋升**。

## 请求算法

```text
L0 准入
 → 资源信号量（Fast/Deep/Shadow 槽）
 → 危险信号量（route_gate → Arc | Cortex）
 → 正检测 − 负检测 → 净分
 → 拦截信号量 Fusion（intercept）→ block | challenge | observe
 → Fast 干净时异步 Shadow（live 深扫）或 Sandbox（候选包，强制不拦）
```

## 运维开关


| 能力        | 开关                                                    | 单请求       |
| --------- | ----------------------------------------------------- | --------- |
| Shadow 深扫 | `NERVE_NATIVE_SHADOW_DEEP`（默认开）                       | Fast 干净自动 |
| 沙箱包       | `NERVE_NATIVE_SANDBOX_PACK` 或 `Engine::mount_sandbox` | 采样自动      |
| 沙箱采样率     | `NERVE_NATIVE_SANDBOX_SAMPLE_BPS`（默认 200=2%）          | —         |
| 整包只观察     | pack `policy.observe_only`                            | 全部        |
| 路径模式      | `NERVE_NATIVE_INSPECT_MODE=auto                       | fast      |


晋升与 allow 合入：**手动**（feedback → export → 审稿 → reload）。

## 代码入口


| 概念    | API / 模块                                                           |
| ----- | ------------------------------------------------------------------ |
| 拦截信号量 | `nerve_antibody_runtime::intercept` · `InterceptPermit`            |
| 正负分   | `FusionEvidence::positive_score` / `negative_score`                |
| 沙箱    | `Engine::mount_sandbox` · `unmount_sandbox` · `health().sandbox`_* |
| 观察环   | `Engine::shadow_recent`（`ShadowRecord.source`）                     |


