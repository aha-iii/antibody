# nerve-antibody-cache

检测热路径缓存（**不改变裁决**，只加速重复干净流量）。

## 模块

| 模块 | 用途 |
|------|------|
| `bloom` | 高置信干净 Bloom 前置 |
| `negative` | Arc 干净短 TTL 负向缓存 |
| `decode_lru` | Cortex decode 视图 LRU |
| `VerdictCache` | 统一门面 |

## 环境变量

`NERVE_NATIVE_CACHE_NEGATIVE` · `NERVE_NATIVE_CACHE_BLOOM` · `NERVE_NATIVE_CACHE_DECODE_LRU`
