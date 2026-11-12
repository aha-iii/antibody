# compile · 编译层

**离线**把契约层的规则编译成 `Program` + `ProgramArtifact`，供 `runtime` 热路径加载。不在请求路径上做 YAML 解析。

| Crate | 职责 |
|-------|------|
| **`nerve-antibody-compiler`** | `compile()`：按 Low/Medium/High 过滤规则 → IR → `Program`；构建 contains 字典与倒排索引、预编译 regex；Artifact JSON 落盘加速冷启动 |
| **`nerve-antibody-signals`** | 解析 pack 内 `signals/signals.yaml`，输出路由 hint（API 正例 lane、fast lane 等），供 `runtime::route_gate` 在 Arc/Cortex 间选型 |

调用链：`Engine::load_pack` / `reload` → 对每档 `NativeLevel` 调用 `compiler::compile()`。

文档：[`docs/arc-cortex/02-compile/`](../../../docs/arc-cortex/02-compile/)
