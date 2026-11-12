# Nerve Arc-Cortex 检测引擎

> **反射级响应，皮层级深检。**  
> Arc-speed response · Cortex-depth inspection

**Arc-Cortex** 是 Nerve 自研 WAF **检测内核**的产品名。工程 crate 使用 `nerve-antibody-*` 前缀（稳定 ABI / 依赖路径）；对外文档、Dashboard、标书统一称 **Arc-Cortex**。

| 对外路径 | 代码 / 指标（暂保留） |
|----------|----------------------|
| **Arc** 路径 | `InspectPath::Fast` · inline fast · Fast 线程池 |
| **Cortex** 路径 | `InspectPath::Deep` · Deep 线程池 · Shadow 异步深扫 |

与 `Nerve-waf`（独立仓库）**并列**：可被 WAF 同进程调用；规则包、验签、发版节奏独立。WAF 侧通过 [`nerve-waf-expert`](05-integration/expert.md) 兼容 facade 接入。

---

## 文档目录

| 层 | 目录 | 内容 |
|----|------|------|
| 总览 | [architecture.md](./architecture.md) | 分层依赖、请求流水线 |
| **中文总览** | [../SYSTEM-ARCHITECTURE-zh.md](../SYSTEM-ARCHITECTURE-zh.md) | 组成图、算法、链路、侧信道（Mermaid） |
| 术语 | [terminology.md](./terminology.md) | Arc/Cortex、L0–L3 |
| **1. 契约** | [01-contract/](./01-contract/) | DSL · Pack · License |
| **2. 编译** | [02-compile/](./02-compile/) | Compiler · Signals |
| **3. 流水线** | [03-pipeline/](./03-pipeline/) | Pipeline · Accel · Semantic · Adaptive · Runtime |
| **4. Facade** | [04-facade/](./04-facade/) | Engine · Cache · Metrics · Admission |
| **5. 集成** | [05-integration/](./05-integration/) | Expert · Dashboard · Bench |
| 规则包 | [packs/](./packs/) | `packs/baseline` 等发版资产 |
| 前端 | [apps/](./apps/) | Arc-Cortex Console 页面 |

**实现细节（主技术文档）：** [`../ENGINE.md`](../ENGINE.md)

---

## 检测能力分层

| 层 | 名称 | 模块 | 能否单独拦截 |
|----|------|------|-------------|
| L0 | 准入 | `nerve-antibody-admission` | 能（CC/Bot/Geo） |
| L1 | 规则 + allow | DSL → Compiler → Runtime | 能 |
| L2 | 语义 | `nerve-antibody-semantic` | 只加分 / veto |
| L3 | 自适应 | `nerve-antibody-adaptive` | **不能**单独 block |

**Arc** 以 L1 为主；**Cortex** 启用 L1 全量 + L2 + L3。

---

## 快速构建

```bash
cargo test
cargo build --release
bash tools/build-with-hyperscan.sh --release   # 在 Nerve-waf 侧构建 Edge+Expert 时
cargo run -p nerve-antibody-dashboard          # Arc-Cortex Console :8790
```
