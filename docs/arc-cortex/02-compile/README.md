# 02 · 编译 / IR 层

DSL → 可执行 **Program**；请求 **feature / fingerprint** 供 L1 与 Arc/Cortex 路由。

| Crate | 文档 | 路径 |
|-------|------|------|
| `nerve-antibody-compiler` | [compiler.md](./compiler.md) | `crates/engine/compile/nerve-antibody-compiler/` |
| `nerve-antibody-signals` | [signals.md](./signals.md) | `crates/engine/compile/nerve-antibody-signals/` |

**输出：** 按 Low/Medium/High 三档各一份 `Program`；可落盘 `ProgramArtifact`（IR 缓存）。
