# nerve-antibody-metrics

运行时原子指标 → Prometheus / JSON。

## 关键指标

| 指标 | Arc-Cortex 含义 |
|------|-----------------|
| `inspect_fast` / `inspect_deep` | Arc / Cortex 次数 |
| `fast_ratio` | Arc 占比 |
| `latency_fast_us_avg` | Arc 平均延迟 |
| `latency_deep_us_avg` | Cortex 平均延迟 |
| `fast_pool_escalate` | Arc 池超时升 Cortex |
| `budget_exhausted` | 预算熔断次数 |
| `stage_*_us_avg` | decode / regex / semantic 分阶段 |

## 类型

- `InspectPath` — `Fast` | `Deep`（文档称 Arc | Cortex）
- `EngineMetrics` · `MetricsSnapshot`

暴露：`GET /metrics` · `GET /api/metrics`（Dashboard）

诊断脚本：`scripts/check-inspect-metrics.sh`
