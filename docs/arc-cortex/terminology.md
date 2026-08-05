# Arc-Cortex 术语

## 产品名

| 名称 | 用法 |
|------|------|
| **Nerve Arc-Cortex** | 全称（文档、标书、Console 标题） |
| **Arc-Cortex Engine** | 英文副标 |
| **NACE** | 可选缩写（Nerve Arc-Cortex Engine） |

Slogan：**反射级响应，皮层级深检。**

## 双路径

| 对外 | 代码 | 含义 |
|------|------|------|
| **Arc** | `InspectPath::Fast` | 反射级：轻 decode、Aho+allow+cheap regex、inline / Fast 池 |
| **Cortex** | `InspectPath::Deep` | 皮层级：全量 decode、tail regex、semantic、adaptive |

环境变量 `NERVE_NATIVE_INSPECT_MODE=auto` 时由 `route_gate` 在 Arc/Cortex 间选择；bench 验收常用 `deep`（全 Cortex）。

## 检测层 L0–L3

| 层 | 产品词 | Crate |
|----|--------|-------|
| L0 | 准入 | `admission` |
| L1 | 签名规则 | `dsl` + `compiler` + `runtime` |
| L2 | 语义 | `semantic` |
| L3 | 自适应 | `adaptive` |

## 与旧称对照

| 旧称 | Arc-Cortex |
|------|------------|
| Native Engine | Arc-Cortex Engine |
| Expert Engine | Arc-Cortex（WAF 集成名仍可称 Expert 段） |
| Fast / Deep | Arc / Cortex |
| nerve-antibody-engine | facade Engine crate（`Engine::inspect`） |
