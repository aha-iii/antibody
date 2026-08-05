# nerve-antibody-engine（Facade）

Arc-Cortex **对外稳定入口**。

## 职责

- `load_pack` / `reload` / `load_pack_with_cache`
- 三包三档 Evaluator（Low · Medium · High）
- `inspect(req, level)` — 编排 cache · plan · pool · shadow

## 子模块

| 模块 | 职责 |
|------|------|
| `engine` | `Engine` · `EngineInner` |
| `pool` | **Arc/Cortex 双线程池**（CPU 自动伸缩 · 分片队列） |
| `shadow` | Fast 干净 → **Cortex 异步**深扫（FN 闭环） |
| `inspect_cache` | 负向缓存 · Bloom 与 engine 桥接 |
| `decode_cache_bridge` | Deep decode LRU 桥接 |
| `health` | 健康快照 |

## Arc 内联

`NERVE_NATIVE_EDGE_INLINE=1` 且 `inline_fast_lane` → 同步 Arc，**不进池**（反射级延迟）。

## 公开 re-export

`NativeRequest` · `NativeHit` · `NativeLevel` · `EngineMetrics`
