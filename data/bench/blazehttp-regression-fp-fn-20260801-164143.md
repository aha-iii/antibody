# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-164143.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 475 |
| detection_rate | 0.0 |
| false_positive_rate | 0.21052631578947367 |
| accuracy | 99.78947368421053 |
| missed | 0 |
| false_positive | 1 |
| malicious_total | 0 |
| normal_total | 475 |
| avg_ms | 765.5494736842105 |
| fail_count | 1 |
| pass_count | 474 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 0 | 0 | +0 |
| `open-redirect-uri-fast` | 9 | 0 | -9 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 0 / FP 1

### FN 样例


### FP Top 15 规则

- `pack.sqli.or-tautology`: 1
