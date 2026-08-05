# 01 · 契约 / 规则语言层

定义「规则长什么样、包怎么加载、商业授权如何解密」，**无 HTTP 副作用**。

| Crate | 文档 | 路径 |
|-------|------|------|
| `nerve-antibody-dsl` | [dsl.md](./dsl.md) | `crates/engine/contract/nerve-antibody-dsl/` |
| `nerve-antibody-pack` | [pack.md](./pack.md) | `crates/engine/contract/nerve-antibody-pack/` |
| `nerve-antibody-license` | [license.md](./license.md) | `crates/engine/contract/nerve-antibody-license/` |

**下游：** `compiler` 消费 DSL AST；`pack` 产出 `NativePack` 供 `Engine` 加载。
