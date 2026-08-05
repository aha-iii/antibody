# Arc-Cortex 架构分层

中文图解（组成、算法、WAF 链路、侧信道）：[SYSTEM-ARCHITECTURE-zh.md](../SYSTEM-ARCHITECTURE-zh.md)

```text
┌─────────────────────────────────────────────────────────────┐
│  05-integration · 应用 / 接入                                │
│  expert · dashboard · bench · (Nerve-waf expert_bridge)      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  04-facade · nerve-antibody-engine                               │
│  Engine · pool(Arc/Cortex) · shadow · inspect_cache         │
│  + cache · metrics · admission(L0)                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  03-pipeline · Domain 检测核心                                 │
│  runtime(Evaluator) · pipeline · semantic · adaptive · accel  │
│  + signals（路由 feature）                                     │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  02-compile · IR                                            │
│  compiler · signals pack                                      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  01-contract · 规则契约                                      │
│  dsl · pack · license                                         │
└─────────────────────────────────────────────────────────────┘

发版资产（非 crate）：packs/baseline/ · packs/demo/ · …
```

## 请求路径（生产）

```text
HTTP → [L0 admission] → Engine::inspect
         → route_gate → Arc 或 Cortex
         → Arc：同步 / Fast 池（反射级）
         → Cortex：Deep 池 / 全量 decode + L2 + L3（皮层级）
         → Fast 干净 → Shadow Cortex 异步（不挡响应）
```

依赖方向：**UI/API → Engine → Runtime → Compiler/Pack**，禁止反向。

## Workspace 物理路径与模块职责

源码级说明见 [`crates/engine/README.md`](../../crates/engine/README.md)。

```text
crates/
├── engine/                    Arc-Cortex 检测内核
│   ├── contract/              规则与发版契约（无在线算法）
│   │   ├── dsl                  规则 AST、字段/谓词/动作、transforms、YAML 加载
│   │   ├── pack                 pack.toml、打包/hash、HMAC 验签与密封发版
│   │   └── license              客户 license / entitlement 校验
│   ├── compile/               离线编译
│   │   ├── compiler             DSL → Program + Artifact；字典/倒排、regex 预编译
│   │   └── signals              signals.yaml → 路由 hint（供 route_gate）
│   ├── pipeline/              在线检测流水线（L1–L3）
│   │   ├── pipeline             多轮 decode、结构解析、视图构建、sidechannel
│   │   ├── accel                Aho-Corasick / Hyperscan 多模加速
│   │   ├── semantic             L2 语义启发式（加分/veto，不单独 block）
│   │   ├── adaptive             L3 浅特征加分（不单独 block）
│   │   └── runtime              Evaluator、Arc/Cortex route_gate、分数融合
│   └── facade/                对外稳定 API
│       ├── nerve-antibody-engine     Engine、双线程池、Shadow 异步深扫
│       ├── cache                Bloom、负向缓存、decode LRU
│       ├── metrics              inspect 指标（Prometheus / JSON）
│       └── admission            L0 准入（CC / Bot / Geo / DDoS）
└── integration/               WAF 接入与应用后端（非引擎内核）
    ├── nerve-waf-expert         WAF 同进程兼容 facade
    ├── nerve-antibody-dashboard   Console Axum API
    └── nerve-antibody-bench     外部 bench HTTP 适配

apps/dashboard/                React Console 前端
packs/                         规则包 YAML/TOML 资产（非 crate）
```

crate 包名仍为 `nerve-waf-native-*`；目录按 Arc-Cortex 逻辑分层归类。
