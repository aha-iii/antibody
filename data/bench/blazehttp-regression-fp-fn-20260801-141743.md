# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-141743.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 1195 |
| detection_rate | 76.92307692307693 |
| false_positive_rate | 40.186125211505924 |
| accuracy | 60.0 |
| missed | 3 |
| false_positive | 475 |
| malicious_total | 13 |
| normal_total | 1182 |
| avg_ms | 10983.627615062762 |
| fail_count | 478 |
| pass_count | 717 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 317 | 7 | -310 |
| `open-redirect-uri-fast` | 9 | 9 | +0 |
| `observe-scanner-generic` | 0 | 0 | +0 |
| `bola-resource-path` | 0 | 0 | +0 |
| `idor-numeric-api` | 0 | 0 | +0 |

## 本次仍失败 FN 3 / FP 475

### FN 样例

- `testcases/56/94/8e1087c5bffe3a7d10ce90e9c72f.black` · DELETE /capture/agnostic?arbitrary=resource
- `testcases/85/f4/e76ed749ed2007368b7e36772410.black` · POST /
- `testcases/d8/ab/654a635915b6333180d6bbe05008.black` · DELETE /integration/mediocre/push/skip?slash=resolver&location=default

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
