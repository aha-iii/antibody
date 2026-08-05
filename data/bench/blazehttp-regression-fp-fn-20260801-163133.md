# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-163133.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 5 |
| detection_rate | 0.0 |
| false_positive_rate | 0.0 |
| accuracy | 100.0 |
| missed | 0 |
| false_positive | 0 |
| malicious_total | 0 |
| normal_total | 5 |
| avg_ms | 529.2 |
| fail_count | 0 |
| pass_count | 5 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 0 | 0 | +0 |
| `open-redirect-uri-fast` | 0 | 0 | +0 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 0 / FP 0

### FN 样例


### FP Top 15 规则

