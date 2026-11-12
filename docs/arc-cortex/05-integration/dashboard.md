# nerve-antibody-dashboard

**Arc-Cortex Console** — 独立 HTTP + React（默认 `:8790`）。

## 后端模块

| 模块 | 职责 |
|------|------|
| `main.rs` | 路由、pack 切换、鉴权 |
| `bench.rs` | 拦截率测试（进程内 Arc/Cortex 指标） |
| `datasets.rs` | blazehttp / gotestwaf 等数据集 |
| `auth_http.rs` | 本地 JWT 登录 |

## 主要 API

| 路径 | 用途 |
|------|------|
| `/api/inspect` | 单条试打 |
| `/api/bench/*` | 拦截率测试 |
| `/api/metrics` | 引擎指标 |
| `/api/shadow/*` | Shadow Cortex 闭环 |
| `/api/admission` | L0 配置 |

启动：`make dashboard`（等价 `bash tools/dev-dashboard.sh`）
