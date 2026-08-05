# blazehttp 回归集复测（FP/FN 问题用例）

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-report-20260801-140221.json`

## 汇总

| 指标 | 值 |
|------|-----|
| total | 2699 |
| detection_rate | 60.60606060606061 |
| false_positive_rate | 44.33608402100525 |
| accuracy | 55.72434234901815 |
| missed | 13 |
| false_positive | 1182 |
| malicious_total | 33 |
| normal_total | 2666 |
| avg_ms | 7894.133012226751 |
| fail_count | 1195 |
| pass_count | 1504 |

## 与上次全量基准对比（Top5 规则 FP）

| rule_id | 上次 FP | 本次回归 FP | 变化 |
|---------|---------|-------------|------|
| `oscmd-windows-unix` | 752 | 317 | -435 |
| `open-redirect-uri-fast` | 643 | 9 | -634 |
| `observe-scanner-generic` | 299 | 0 | -299 |
| `bola-resource-path` | 268 | 0 | -268 |
| `idor-numeric-api` | 170 | 0 | -170 |

## 本次仍失败 FN 13 / FP 1182

### FN 样例

- `testcases/47/e8/60f3f244ef8fb130a8e7fe597184.black` · GET /uploadfiles/apache.php.jpeg
- `testcases/4b/0a/096825fe5d589a0fe75c44aca53e.black` · GET /mailsms/s?func=ADMIN:appState&dumpConfig=/
- `testcases/56/94/8e1087c5bffe3a7d10ce90e9c72f.black` · DELETE /capture/agnostic?arbitrary=resource
- `testcases/81/0f/7a42faed086036e72fec24ba965e.black` · DELETE /?protocol=database
- `testcases/85/f4/e76ed749ed2007368b7e36772410.black` · POST /
- `testcases/89/ec/26b7057003ad7a963dfe10ae6c5d.black` · POST /uc/feedback/api/v1/pc/feedback/add
- `testcases/90/e5/70482595612794ff59a421bd0fd8.black` · GET /uploadfiles/apache.php.jpeg
- `testcases/a5/7f/bbda3bb3a6d78649b617f43ce411.black` · GET /?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
- `testcases/be/32/cbb9261c728de3c91a11a7bd086d.black` · POST /inner/indecisive/internal/vice%20versa?resilient=capture&under%20the%20hoo
- `testcases/d8/ab/654a635915b6333180d6bbe05008.black` · DELETE /integration/mediocre/push/skip?slash=resolver&location=default
- `testcases/e0/34/4df7fcb63604d3ea54a7a48d5ebb.black` · POST /example/tree/a/search
- `testcases/f1/ab/b3a62798fee9bf0979c265b5d19c.black` · HEAD /notation/heterogeneous?ellipsis=scalability&introspect=migrate&region=moni
- `testcases/f7/9a/58717bea9d5ba7be841929a453b4.black` · POST /run

### FP Top 15 规则

- `oscmd-windows-unix`: 317
- `open-redirect-param`: 200
- `xpath-injection`: 153
- `forced-browsing-admin`: 109
- `proto-anomaly-marker`: 99
- `encoded-evasion-probe`: 75
- `sqli-shutdown-udf`: 48
- `bola-enumeration-query`: 42
- `http-smuggle-cl-anomaly`: 26
- `attack-signature-cluster`: 14
- `ssrf-odd-schemes`: 10
- `open-redirect-uri-fast`: 9
- `cache-poison-header-smuggle`: 7
- `mail-protocol-crlf-inject`: 6
- `ssrf-rebinding-meta`: 6
