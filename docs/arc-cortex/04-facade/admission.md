# nerve-antibody-admission

**L0 准入**（在 L1 规则之前）。

## 模块

| 模块 | 职责 |
|------|------|
| `cc` | 单机 token bucket 限流 |
| `bot` | Bot 启发式 |
| `geo` | Geo 国家/地区 |
| `ddos` | 配置占位；真实洪泛 → **Nerve-ddos** |

## 边界

IP 黑白名单 / 连接级 DDoS **不在** Arc-Cortex L1。见 [`../../BOUNDARY-IP-GEO-RATE.md`](../../BOUNDARY-IP-GEO-RATE.md)。

Dashboard：`/api/admission` · ConfigPages。
