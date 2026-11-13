# Nerve Arc-Cortex Engine

> **Nerve Arc-Cortex**（弧-皮层检测引擎）· *反射级响应，皮层级深检。*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](CHANGELOG.md)

Antibody（**Nerve-antibody**）为 WAF 套件 **Nerve WAF** 的检测引擎子产品，可被 Nerve WAF 同进程调用；本仓库独立发版，规则包与引擎节奏解耦。

**产品文档（按层分目录）：** [`docs/arc-cortex/README.md`](docs/arc-cortex/README.md)  
**系统架构总览（中文）：** [`docs/SYSTEM-ARCHITECTURE-zh.md`](docs/SYSTEM-ARCHITECTURE-zh.md)  
**实现细节：** [`docs/ENGINE.md`](docs/ENGINE.md)

## 能力（摘要）

| 能力 | 说明 |
|------|------|
| 规则语言 | `when.all/any`、transforms、`block/observe/allow`、`min_level` |
| 三档烈度 | Low/Medium/High 独立 Program + `threshold_by_level` |
| 编译器 | DSL → `Program` / Artifact；contains 字典 + 倒排索引 |
| 运行时 | Aho 预过滤、FieldCache、评分融合 |
| L2 语义 | SQL/XSS/Path 启发式 + veto |
| L3 自适应 | 浅特征加分（不可单独拦截） |
| 加速 | 默认 aho-corasick；Hyperscan feature 占位 |
| 发版 | 内容哈希 + 可选 HMAC；`Engine::reload` |

完整说明见 [`docs/ENGINE.md`](docs/ENGINE.md)。

## Workspace（逻辑分层）

完整 crate 说明见 [`docs/arc-cortex/architecture.md`](docs/arc-cortex/architecture.md)。

| 层 | 目录 |
|----|------|
| **引擎** | `crates/engine/` — contract · compile · pipeline · facade |
| 集成 | `crates/integration/` — expert · dashboard · bench |
| 外部副本 | `crates/external/` — 自 `Nerve-waf` 复制的 canonical · core · inspect-trace · auth，见该目录 [README](crates/external/README.md) |
| 前端 | `apps/dashboard/` — React Console |

## 安装

```bash
bash install.sh              # 依赖自检 + release 构建 + 跑测试
bash install.sh --skip-test  # 只构建
bash install.sh --with-ui    # 额外构建 Console 前端
```

等价 Make 目标：`make install` / `make build` / `make test` / `make fmt` / `make clippy`（`make help` 查看全部）。

本仓库是引擎库，产物由 Nerve WAF 以 path 依赖调用；单独验证请用下节 Dashboard。

## Build

```bash
cargo test
cargo build --release
cargo build -p nerve-antibody-engine --features accel-hyperscan
```

## Dashboard（Arc-Cortex Console）

React 前端 + Axum API，不依赖仓库外的 `Nerve-waf`。

```bash
# 一键：API :8790 + Vite :5178（依赖自动安装、健康检查、Ctrl+C 双停）
bash tools/dev-dashboard.sh
# 装了 make 的环境可简写：make dashboard
# 浏览器打开 http://127.0.0.1:5178
```

手动分两个终端：

```bash
# 1) 构建 UI（首次 / 改前端后；一键脚本开发模式可不 build）
cd apps/dashboard && npm install && npm run build && cd ../..

# 2) 启动
cargo run -p nerve-antibody-dashboard
# 本机 http://127.0.0.1:8790
# 局域网 http://<你的IP>:8790
```

开发热更新（两个终端，等价于 `make dashboard`）：

```bash
cargo run -p nerve-antibody-dashboard
cd apps/dashboard && npm run dev   # http://127.0.0.1:5178 ，/api 代理到 8790
```

| 环境变量 | 默认 | 说明 |
|----------|------|------|
| `LISTEN` | `0.0.0.0:8790` | 监听地址（局域网可用 `http://<IP>:8790`） |
| `PACK_ROOT` | `<repo>/packs` | 规则包根目录 |
| `DEFAULT_PACK` | `baseline` | 启动包（页面可切 `demo` / `community-crs`） |
| `UI_DIST` | `apps/dashboard/dist` | React 构建产物目录 |

案例库：`packs/baseline/samples/<category>/<rule_id>.yaml`（与规则文件一一对应）。Dashboard 菜单「案例库」可筛选、一键检测、加载到试打。扁平样本可拆分：`python3 packs/baseline/tools/split_samples_by_rule.py`。

UI 使用 `apps/dashboard/vendor/nerve-ui`（`@nerve/ui` 源码副本，与 WAF Console 同款侧栏 / ant-* 样式）。该副本随仓库提供，单独 clone 即可构建，不需要仓库外的同级目录；详见该目录下的 `README.md`。

## 规则包

| 包 | 说明 |
|----|------|
| `packs/community-crs/` | OWASP CRS `@rx` 翻译为本引擎 YAML（约 219 条，默认优先） |
| `packs/baseline/` | 自研高信号底盘 |
| `packs/demo/` | 单测 |

详见 [`packs/SOURCES.md`](packs/SOURCES.md)。

## 被 Nerve-waf 接入

`nerve-waf-inspect` path 依赖本仓库 compat facade（`nerve-waf-expert`）；环境变量：

| 变量 | 作用 |
|------|------|
| `NERVE_NATIVE_PACK` | 规则包目录 |
| `NERVE_NATIVE_ENGINE=off` | 关闭本引擎，WAF 回退 WASM/Coraza |

## 文档

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [SECURITY.md](./SECURITY.md)
- [CHANGELOG.md](./CHANGELOG.md)

## License

[MIT](./LICENSE)
