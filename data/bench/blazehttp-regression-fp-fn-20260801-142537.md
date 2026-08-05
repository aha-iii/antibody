# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-142537.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 478 |
| detection_rate | 100.0 |
| false_positive_rate | 100.0 |
| accuracy | 0.6276150627615062 |
| missed | 0 |
| false_positive | 475 |
| malicious_total | 3 |
| normal_total | 475 |
| avg_ms | 4356.533472803348 |
| fail_count | 475 |
| pass_count | 3 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 7 | 7 | +0 |
| `open-redirect-uri-fast` | 9 | 9 | +0 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 0 / FP 475

### FN 样例


### FP Top 15 规则

- `open-redirect-param`: 107
- `encoded-evasion-probe`: 74
- `bola-enumeration-query`: 61
- `sqli-shutdown-udf`: 48
- `forced-browsing-admin`: 30
- `open-redirect-proto-rel`: 27
- `http-smuggle-cl-anomaly`: 26
- `open-redirect-uri-fast`: 9
- `ssrf-odd-schemes`: 7
- `oscmd-windows-unix`: 7
- `mail-protocol-crlf-inject`: 6
- `cache-poison-header-smuggle`: 6
- `ssrf-rebinding-meta`: 6
- `attack-signature-cluster`: 6
- `xss-event-handler-sink`: 5
