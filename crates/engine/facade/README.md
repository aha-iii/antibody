# facade · Engine 封装

**对外唯一推荐依赖面**。WAF（`nerve-waf-expert`）、Console、Bench 应只调用 `nerve-antibody-engine::Engine`，不直连 pipeline/compile。

| Crate | 职责 |
|-------|------|
| **`nerve-antibody-engine`** | `Engine`：`load_pack` / `reload` / `inspect`；三包三档 Evaluator；**Arc/Cortex 双线程池**（CPU 自动伸缩、分片队列）；Fast 干净后 **Shadow Cortex** 异步深扫；健康快照 |
| **`nerve-antibody-cache`** | Bloom 预过滤、负向缓存（干净请求短路）、decode LRU 策略与容量控制 |
| **`nerve-antibody-metrics`** | `EngineMetrics`：inspect 次数、Arc/Cortex 比例、延迟分位、pool 排队/升级计数；Prometheus text 与 JSON |
| **`nerve-antibody-admission`** | **L0 准入**：CC 限速、Bot 识别、Geo 阻断、DDoS 阈值；在 L1 之前可独立返回 block |

```text
HTTP 请求
  → admission (L0，可选)
  → Engine::inspect
       → cache 查/写
       → runtime plan (Arc/Cortex)
       → pool 或 inline Arc
       → shadow 异步 Cortex
  → NativeHit + metrics
```

文档：[`docs/arc-cortex/04-facade/`](../../../docs/arc-cortex/04-facade/)
