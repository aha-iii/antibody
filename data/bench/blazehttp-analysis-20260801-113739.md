# blazehttp FP / FN 分析与对策

- 报告: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-report-20260801-113739.json`
- 回归清单: `/mnt/d/workspace/waf/Nerve-waf-native/data/bench/blazehttp-regression-latest.json`
- 生成: 2026-08-01T16:26:38

## 汇总

| 指标 | 值 |
|------|-----|
| total | 33877 |
| detection_rate | 94.98480243161094 |
| false_positive_rate | 8.025527559529184 |
| accuracy | 92.03294270448977 |
| missed | 33 |
| false_positive | 2666 |
| malicious_total | 658 |
| normal_total | 33219 |

## FN（漏报）33 条

恶意样本应 block 但 pass。

### 典型原因

- 规则面未覆盖（复杂编码、multipart、业务 API 路径）
- 仅 `decode.attack_hint` 加分未过阈
- Deep 预算熔断前未命中 block 规则

### 按 rule_id

- `(none)` × 25 — 补 L1 签名或 L2 semantic；登记到 packs/baseline/samples
- `decode.attack_hint` × 7 — FN：decode 仅 hint 未定罪 — 补 L1 规则或降低 hint-only 依赖
- `sqli-waitfor` × 1 — FN：WAITFOR 变体 — 补 sqli-evasions 或 semantic SQLi

### 样例

| id | request | detail |
|----|---------|--------|
| `testcases/47/e8/60f3f244ef8fb130a8e7fe597184.black` | GET /uploadfiles/apache.php.jpeg |  |
| `testcases/4b/0a/096825fe5d589a0fe75c44aca53e.black` | GET /mailsms/s?func=ADMIN:appState&dumpConfig=/ | decode_attack_hint |
| `testcases/56/94/8e1087c5bffe3a7d10ce90e9c72f.black` | DELETE /capture/agnostic?arbitrary=resource |  |
| `testcases/72/aa/d3e7a27c400b62bc613c0712713f.black` | POST /vulnerabilities/exec/ |  |
| `testcases/72/e8/a9844141172d21301725da11c5dc.black` | POST /vulnerabilities/sqli/session-input.php | decode_attack_hint |
| `testcases/73/2c/4a23d9387606994afb347d0791dd.black` | POST /?q=node&destination=node |  |
| `testcases/73/81/da87ccf03256c0a4f316afe35e04.black` | GET /vulnerabilities/xss_r/?name=%3Ca+href%3D%23+download%3D%22filenam |  |
| `testcases/73/f6/3446c32eb41eba6a2592fd277e50.black` | GET /vulnerabilities/xss_r/?name=self%5B%27%5Cu%7B0061%7D%5Cu%7B006c%7 | decode_attack_hint |
| `testcases/75/36/e3b4bc5a5f270b73aa0ae99e1585.black` | GET /error.html?templates[]=1&templateidlist=O:20:%22vB_Image_ImageMag |  |
| `testcases/7e/9e/1c9218f848c24774544b11e42ca0.black` | POST /on-premise/mode?marry=UENGRVQwTlVXVkJGSUdadmJ5QmJJRHdoUlU1VVNWUl |  |
| `testcases/81/0f/7a42faed086036e72fec24ba965e.black` | DELETE /?protocol=database |  |
| `testcases/85/f4/e76ed749ed2007368b7e36772410.black` | POST / |  |
| `testcases/88/ce/f98074efd41e87e423eadb55f9da.black` | GET /vulnerabilities/xss_r/?name=self%5B%28%2B%7B%7D%2B%5B%5D%29%5B%2B |  |
| `testcases/89/ec/26b7057003ad7a963dfe10ae6c5d.black` | POST /uc/feedback/api/v1/pc/feedback/add |  |
| `testcases/8a/84/48688a7932084254d649819d4362.black` | GET /element/inherit/state?refresh=populate |  |
| `testcases/8e/63/eece52f3a9783bc3c8dd5802b5cf.black` | GET / |  |
| `testcases/8e/6e/c039ad4b8aa58ed2ebcab0e08936.black` | GET / |  |
| `testcases/90/e5/70482595612794ff59a421bd0fd8.black` | GET /uploadfiles/apache.php.jpeg |  |
| `testcases/93/06/2d8a3f206d7c7f50c577ddd04333.black` | POST /druid/indexer/v1/sampler?for=connect |  |
| `testcases/9b/ea/0d232d76fa78412049c8048b6f25.black` | GET / |  |

## FP（误报）2666 条

白样本应 pass 但被 block。

### 处理优先级

1. **收紧 Top 规则**（见下表）— 提高 min_level、加 feature 门闩
2. **90-allow** — OAuth/代理头/JWT/搜索场景（见 packs/baseline/FALSE_POSITIVES.md）
3. **登记** false-positives.yaml — 暂无法收紧的个案

### 按 rule_id Top 15

| rule_id | 次数 | 建议 |
|---------|------|------|
| `oscmd-windows-unix` | 752 | 路径/UA 扫描误伤：提高 min_level、要求 shell 元字符组合，或加 90-allow（静态资源/health） |
| `open-redirect-uri-fast` | 643 | 正常 redirect_uri / OAuth：用 feature+fingerprint allow，勿放宽 block 规则 |
| `observe-scanner-generic` | 299 | Scanner UA 误伤白流量：改 observe-only 或绑定 scanner fingerprint |
| `bola-resource-path` | 268 | REST 路径数字 ID 误伤：收紧为 admin/api + 敏感动词组合 |
| `idor-numeric-api` | 170 | 同上：numeric path 需配合 BOLA feature，避免裸 /users/123 |
| `proto-anomaly-marker` | 99 | 协议头异常过宽：拆分到具体 smuggle/CRLF 规则 |
| `forced-browsing-admin` | 97 | admin 路径误伤：要求 combined with 401/403 响应或敏感扩展名 |
| `encoded-evasion-probe` | 73 | 编码探测误伤正常 encoded 参数：提高阈值或 min_level→high |
| `sqli-shutdown-udf` | 48 | 文档/SQL 字样误伤：min_level→high + 引号/information_schema 门闩 |
| `open-redirect-param` | 38 | 收紧谓词或 min_level→high；必要时 90-allow |
| `xpath-injection` | 31 | 收紧谓词或 min_level→high；必要时 90-allow |
| `open-redirect-proto-rel` | 27 | 收紧谓词或 min_level→high；必要时 90-allow |
| `http-smuggle-cl-anomaly` | 26 | 收紧谓词或 min_level→high；必要时 90-allow |
| `path.forced_admin` | 16 | 收紧谓词或 min_level→high；必要时 90-allow |
| `bola-enumeration-query` | 14 | 收紧谓词或 min_level→high；必要时 90-allow |

## 下次只测问题用例

```bash
# Dashboard 数据源选「blazehttp 回归（仅 FP/FN）」
# 或 CLI：
curl -X POST http://127.0.0.1:8790/api/bench/start \
  -H "Content-Type: application/json" \
  -d '{"dataset":"blazehttp-regression","level":"medium","concurrency":40}'
```
