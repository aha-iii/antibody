# crates · Rust workspace

所有 Rust 源码在此目录。

## engine · Arc-Cortex 检测内核

```text
crates/engine/
├── contract/          规则与发版契约（dsl · pack · license）
├── compile/           离线编译（compiler · signals）
├── pipeline/          在线检测流水线（pipeline · accel · semantic · adaptive · runtime）
└── facade/            对外 Engine API（nerve-antibody-engine · cache · metrics · admission）
```

**各模块职责说明：** [`engine/README.md`](engine/README.md)

## integration · 接入与应用后端

| 子目录 | 职责 |
|--------|------|
| `nerve-waf-expert` | Nerve-waf 兼容 facade，re-export `Engine` 供同进程 inspect |
| `nerve-antibody-dashboard` | Arc-Cortex Console 的 Axum HTTP API |
| `nerve-antibody-bench` | blazehttp 等外部 bench 工具的 HTTP 适配 |

可运行 **React 前端** 在 [`../apps/dashboard/`](../apps/dashboard/)；**规则包** 在 [`../packs/`](../packs/)（非 crate）。
