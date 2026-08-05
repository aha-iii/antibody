# 04 · Facade + 运行时设施

对外 **`Engine`** 与热路径配套：线程池、缓存、指标、L0 准入。

| Crate | 文档 | 路径 |
|-------|------|------|
| `nerve-antibody-engine` | [engine.md](./engine.md) | `crates/engine/facade/nerve-antibody-engine/` |
| `nerve-antibody-cache` | [cache.md](./cache.md) | `crates/engine/facade/nerve-antibody-cache/` |
| `nerve-antibody-metrics` | [metrics.md](./metrics.md) | `crates/engine/facade/nerve-antibody-metrics/` |
| `nerve-antibody-admission` | [admission.md](./admission.md) | `crates/engine/facade/nerve-antibody-admission/` |

稳定 API：`nerve_antibody_engine::Engine::inspect()`。
