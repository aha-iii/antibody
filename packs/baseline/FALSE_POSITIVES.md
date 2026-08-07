# blazehttp 误报处理说明（baseline）

对照：Dashboard `api/bench` · dataset=`blazehttp` · 白样本 `expect=pass` 却被 `block`。

完整历史清单可参考 [`false-positives.yaml`](./false-positives.yaml)。  
**处理原则：能收紧规则就收紧；不靠切换 community-crs。**

## 判定

| 类型 | 含义 | 处理 |
|------|------|------|
| **真误报** | 正常业务流量（搜索/埋点/CSP 报告/编辑器）被拦 | **收紧规则**（本轮已做） |
| **灰区** | 正文里带攻击字样的白流量（如搜索 `union select`） | 收紧到「更像注入」再拦 |
| **可接受误报** | 严格档（high）才启用的宽规则 | 升 `min_level`，默认 medium 不启用 |

## 本轮已改规则（2026-07-25）

| 规则 | 误报形态 | 怎么处理 |
|------|----------|----------|
| `xss-concat-alert` | CSP report JSON 命中 `doc…ument` / `eval` 拼接正则 | 必须出现在 `window/top/self[...]` 或 `['ale'+'rt']`；`min_level`→medium |
| `xss-js-hex-alert` | `js_unescape` 后普通 `alert(` 也中 | **不再**解完再匹配 `alert(`；只匹配 `\x61\x6c…` / `\u0061…` 转义串 |
| `xss-javascript-uri` / `xss-entity-javascript` | 埋点 `javascript:void(0)` | 排除 `void`；要求 `alert/eval/document/...` |
| `xss-script-tag` | 搜索/JSON 里裸 `<script` | 改为 `<script[\s/>]` 标签形 |
| `xss-script-close` | 在线 IDE body 含 `</script>` | uri/query 仍拦；body 收紧；`min_level`→medium |
| `xss-svg-onload` | 日志里裸 `<svg` | 去掉裸 `<svg`，必须带 `onload/onerror=…` |
| `sqli-union-select` | 搜索「union select 关键字」 | 去掉「空格+union」；要求引号前缀或 `select null/from/--` |
| `sqli-into-outfile` | GetHints / 文案含 into outfile | 必须 `into outfile '` 带引号路径 |
| `sqli-select-from` | 文档/SQL 教程字样 | `min_level`→**high**，并要求引号/information_schema 等 |
| `rce-nc-rev` | 正文偶发 `ncat ` | 去掉裸 `ncat `；要求 `-e` 或 IP |

## 业务 FP 缓解（OAuth / 代理头 / JWT）

这些形态**不要**靠收紧语义包里的 SQLi/XSS 正则；用 L1 `feature` / `fingerprint` / `length_gt` + `action: allow`。

| 误报形态 | 缓解 | 规则 / 信号 |
|----------|------|-------------|
| Keycloak / OAuth token 交换、`redirect_uri` 授权跳转 | `action: allow` + feature/fingerprint | `rules/90-allow/oauth-token-exchange-allow.yaml`（`oauth_token_exchange` ∧ `keycloak_token_path`；或 `oauth_redirect_uri` ∧ `oauth_auth_path`） |
| 反代 `X-Original-URL`（非 TE 走私） | `action: allow` + feature | `rules/90-allow/proxy-x-original-url-observe.yaml`（`proxy_x_original_url`） |
| 正常 Bearer JWT 被当超长异常 | `length_gt: 4096` 才定罪；普通 token 远低于阈值 | `rules/09-known-bad/jwt-oversized.yaml`（Authorization / Cookie / query `access_token`\|`token`）；辅助信号 `signals.yaml` → `long_authorization`（`length_gt` 2048） |

语义层注释见 `semantic/signatures.yaml` 文件头：禁止用语义匹配 `grant_type=` / `Bearer eyJ…` 等 OAuth 正文。

## WAFTester medium（2026-08 分类治理 B1–B5）

对照：`scripts/_quick-bench.sh waftester medium`。原则不变：**真误报收紧规则**，禁止宽 `90-allow` 顶替。

| 规则 | 误报/漏报形态 | 怎么处理 |
|------|---------------|----------|
| `jwt-access-token-anomaly` | 任意合法 JWT `access_token=` 被拦 | 删除宽三段 JWT 正则；只留 fake-signature / 空段 / 段数异常 |
| `sensitive-api-recon` | `/rest/workflows`、OAuth/SAML 裸路径 | 删路径宽匹配；n8n 危险 query 另立 `n8n-workflow-expr-abuse`（`min_level: high`） |
| `http-smuggle-cl-te` | `TE: identity\|gzip` 白样本 | 只拦非法 TE（cow 等）与 CL+TE 共存 / 重复 CL |
| `transfer-encoding-smuggle` | `TE: chunked` 命中 `*chunk*` | 去掉合法 chunked 宽匹配 |
| `proto-crlf-protocol-inject` | 合法 `Sec-WebSocket-*` 多头 | 头字段只认编码 `%0d%0a`，勿用裸换行 |
| `proto-anomaly-marker` | Immich chunked 上传标 `chunk-anomaly` | 从定罪列表去掉 `chunk-anomaly` |
| `legit-api-dup-header-allow` | 根路径 `/` 放行恶意 dup | 去掉 `/`；仅纯 `dup-header` + `/api/*` |
| `open-redirect-param` | `q=redirect_uri=https://legitimate…` | 改用 `uri` + `[?&]` 锚定，避免 `query.q` 值内嵌误报 |
| `open-redirect-misc` | `q=//attacker` / `/%2f%2f` 漏报 | 补协议相对与双编码斜杠 |
| `rce-windows-lolbin` / `rce-python-c` / `rce-cmd-*` | 编码载荷漏报 | `url_decode_uni` + 灵活空白；新增 `rce-cmd-var-concat` / `rce-cmd-for-loop` |
| `fuzz-double-encode-control` / `sqli-null-byte-keyword` | `%2500` / `SEL%2500ECT` | 双解码控制字符与关键字分裂 |

样本：各规则对应 `packs/baseline/samples/**` 均补正负对。

## GoTestWAF texts / Base64Flat（2026-08 · 1.5.51）

| 规则 | 误报/漏报形态 | 怎么处理 |
|------|---------------|----------|
| `pack.sqli.union-select-seq` | 「union was a great select」 | seq `score_delta=0` + `prose.union-veto` |
| `sqli-auth-bypass-tail-comment` | `D'or 1st parfume` | `or`+数字后须 `=`/`--`/`#` 等，勿跟字母序数 |
| `injection-ssi-xpath-ldap` | 书名 `JavaScript: Basics…` | 仅混淆拆分或 `javascript:`+攻击 API |
| `proto-crlf-protocol-inject` | 文案含 `subject`/`set`/`COOKIE` | CRLF 后须 `set KEY` / `subject:` |
| `blazehttp-gap-path-probes` | `DELETE 75oBC$` | 须 `METHOD /` 走私形 |
| `sqli-shutdown-udf` | `_SELECT … fromDate` | `\bfrom\b` + 空白 + 标识符 |
| `legit-api-search-get-allow` | 整段 base64 `q=` 被 allow 压掉攻击分 | 仅短词或含空白的搜索词 |
| `gotestwaf-base64-flat` | OWASP Base64Flat 漏报 | 已知攻击 base64 前缀 L1 |
| decode_attack_hint / xss_kw | 书名 `JavaScript: Basics…` → challenge | `javascript:` 仅认 alert/eval/… 载荷 |

## 高并发假漏报（2026-08）

UI 选 **并发 80** 时，若预算过紧，失败用例耗时会顶在 `max_inspect_ms`，引擎熔断返回 `pass`（`detail` 空）。

- 包默认（1.5.48）：`[policy.levels.medium] max_inspect_ms = 5000`（见 `pack.toml` 注释）
- 分流与优先修：[`WAFTTEST-FAIL-TRIAGE.md`](./WAFTTEST-FAIL-TRIAGE.md)
- 评测建议并发 **24–40**；改包后需**重启 Dashboard** 重载

## 你怎么验证

1. 重载 baseline：`POST /api/reload` 或 Dashboard「切换/重载包」  
2. 再跑 blazehttp / waftester（建议 **medium**）  
3. 看误报率是否下降；若个别仍 FP，把 `rule_id` + `request_summary` 记进 `false-positives.yaml` 再针对性收
