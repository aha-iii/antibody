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

## 你怎么验证

1. 重载 baseline：`POST /api/reload` 或 Dashboard「切换/重载包」  
2. 再跑 blazehttp（建议 **medium**）  
3. 看误报率是否下降；若个别仍 FP，把 `rule_id` + `request_summary` 记进 `false-positives.yaml` 再针对性收
