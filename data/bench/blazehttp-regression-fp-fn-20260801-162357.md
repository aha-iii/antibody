# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-162357.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 44 |
| detection_rate | 0.0 |
| false_positive_rate | 11.363636363636363 |
| accuracy | 88.63636363636364 |
| missed | 0 |
| false_positive | 5 |
| malicious_total | 0 |
| normal_total | 44 |
| avg_ms | 736.1590909090909 |
| fail_count | 5 |
| pass_count | 39 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 0 | 0 | +0 |
| `open-redirect-uri-fast` | 0 | 0 | +0 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 0 / FP 5

### FN 样例


### FP Top 15 规则

- `pack.xss.script-tag`: 3
- `pack.path.traversal`: 2
