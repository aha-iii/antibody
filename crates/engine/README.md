# engine · Nerve Arc-Cortex 检测内核

**Arc-Cortex** 引擎全部 Rust 源码。按 **契约 → 编译 → 流水线 → 封装** 单向依赖组织；crate 包名为 `nerve-antibody-*`。

WAF 接入、Console、Bench 在 [`crates/integration/`](../integration/)，不属于本目录。

完整产品文档：[`docs/arc-cortex/README.md`](../../docs/arc-cortex/README.md)

---

## 目录与职责

```text
crates/engine/
├── contract/          规则与发版的「数据结构契约」—— 不含检测算法
│   ├── dsl            规则 YAML 的 AST、字段/谓词/动作、transforms、加载校验
│   ├── pack           规则包 manifest、目录打包、版本/hash、可选 HMAC 验签与密封
│   └── license        规则包 license 校验（客户发版、功能 entitlement）
│
├── compile/           规则「离线编译」—— 把 YAML 变成可执行 Program
│   ├── compiler       DSL → IR → Program + Artifact；contains 字典/倒排、regex 预编译
│   └── signals        读 pack 内 signals.yaml，生成路由 hint 供 runtime route_gate 用
│
├── pipeline/          检测「在线流水线」—— 请求 decode、匹配、语义、融合（L1–L3 核心）
│   ├── pipeline       多轮 decode（url/base64/recursive）、XML/结构解析、视图构建、sidechannel
│   ├── accel            多模串加速：默认 Aho-Corasick；可选 Hyperscan feature
│   ├── semantic         L2 语义启发式（SQL/XSS/Path 等），加分或 veto，**不能单独 block**
│   ├── adaptive         L3 浅特征加分（Engram hook），**不能单独 block**
│   └── runtime          Evaluator：route_gate 选 Arc/Cortex、plan_inspect、规则匹配与分数融合
│
└── facade/            对外稳定 API 与运行态设施 —— WAF/Console 只应依赖这一层
    ├── nerve-antibody-engine   Engine 入口：load/reload/inspect；Arc/Cortex 双线程池；Shadow 异步深扫
    ├── cache                Bloom 预过滤、负向缓存、decode LRU 策略
    ├── metrics              inspect 计数/延迟/fast_ratio 等，Prometheus 与 JSON 导出
    └── admission            L0 准入：CC 限速、Bot、Geo、DDoS 阈值（可先于 L1 直接拦截）
```

---

## 分层与检测能力对照

| 逻辑层 | 目录 | 检测层 | 能否单独拦截 |
|--------|------|--------|-------------|
| contract | `contract/` | —（规则定义） | — |
| compile | `compile/` | —（离线编译） | — |
| pipeline | `pipeline/runtime` + `pipeline/pipeline` | **L1** 签名规则 | 能 |
| pipeline | `pipeline/semantic` | **L2** 语义 | 否（加分/veto） |
| pipeline | `pipeline/adaptive` | **L3** 自适应 | 否 |
| facade | `facade/admission` | **L0** 准入 | 能 |
| facade | `facade/nerve-antibody-engine` | 编排 Arc/Cortex | — |

**Arc** 路径以 L1 为主（轻 decode + 快速匹配）；**Cortex** 走 L1 全量 + L2 + L3。

---

## 依赖方向

```text
facade → pipeline → compile → contract
```

- `contract`：无引擎内上游依赖
- `compile`：读 `dsl` / `pack`
- `pipeline`：读 `compile` 产出的 `Program`，`runtime` 编排各子模块
- `facade`：组装 `Engine`，对接 cache / metrics / admission，**唯一推荐的外部调用面**

---

## 各层详细文档

| 层 | README | arc-cortex 文档 |
|----|--------|-----------------|
| contract | [contract/README.md](contract/README.md) | [01-contract/](../../docs/arc-cortex/01-contract/) |
| compile | [compile/README.md](compile/README.md) | [02-compile/](../../docs/arc-cortex/02-compile/) |
| pipeline | [pipeline/README.md](pipeline/README.md) | [03-pipeline/](../../docs/arc-cortex/03-pipeline/) |
| facade | [facade/README.md](facade/README.md) | [04-facade/](../../docs/arc-cortex/04-facade/) |
