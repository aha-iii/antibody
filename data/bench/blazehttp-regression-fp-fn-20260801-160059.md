# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-160059.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 475 |
| detection_rate | 0.0 |
| false_positive_rate | 9.263157894736842 |
| accuracy | 90.73684210526316 |
| missed | 0 |
| false_positive | 44 |
| malicious_total | 0 |
| normal_total | 475 |
| avg_ms | 874.9094736842105 |
| fail_count | 44 |
| pass_count | 431 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 7 | 0 | -7 |
| `open-redirect-uri-fast` | 9 | 0 | -9 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 0 / FP 44

### FN 样例


### FP Top 15 规则

- `path.forced_admin`: 30
- `pack.xss.script-tag`: 3
- `pack.path.traversal`: 3
- `pack.rce.shell-metachar`: 2
- `rce.shell_meta`: 2
- `redirect.open`: 2
- `jwt.missing_sig`: 1
- `jwt.header_x5t`: 1
