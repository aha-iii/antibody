# WAFTester medium 失败分流与优先修清单（2026-08）

对照失败表：期望 | 实际 | 命中规则 | 耗时。

## A. 预算假漏报（优先抬预算）

**特征：** 黑→pass，明细 `—`，耗时 ≈ `levels.medium.max_inspect_ms`（原 2500）或略高。

**覆盖面（体量最大）：** IDOR/BOLA/BFLA、PROTO-SMUG-*、XXE、部分 NoSQL/缓存/JWT、强制浏览。

**动作：**
1. `pack.toml` → `[policy.levels.medium] max_inspect_ms` 提到 **5000**（high 同步）
2. 评测并发建议 **24–40**；改完**重启 Dashboard**
3. 验证：`budget_exhausted` 下降后，空明细 FN 应明显减少

## B. Allow / 融合扣分（有 rule_id，非超时）

融合：`有效分 = rule_score - allow_score`。allow 分 ≥ 攻击分 → 变 pass。

| 优先级 | 现象 | 规则 | 修法 |
|--------|------|------|------|
| P0 | JWT 负 iat 等黑样本被放 | `auth-jwt-regression-allow`（含 `mlhdci6lte`） | 删除「凡负 iat 即 allow」分支；白样本改靠更窄标记 |
| P0 | `/api/users/me*` 提权黑样本被放 | `api-self-me-allow` score=50 | 仅 GET 安全读路径；禁止 `/promote`；突变方法不 allow |
| P0 | OAuth evil/lookalike redirect 被放 | `oauth-authorize-flow-allow` 过宽 | 去掉无路径约束的 `response_type=code`；强化 override |
| P1 | WebDAV 白样本（MKCOL 等）被拦 | `query-injection-crlf-command` | 排除 `q=` 以 WebDAV 方法开头的报文样例 |
| P1 | JWE 五段白样本被拦 | `jwt-access-token-anomaly` 段数≥4 | 排除 enc/A128KW 等 JWE |
| P1 | n8n `{{$json.__proto__` 白样本 | `proto-pollution` | 排除 `{{$json.` 表达式内嵌 |
| P1 | EXIF 字段带 `<script` 白样本 | `pack.xss.script-tag` 等 | 限定非 media upload 参数或收紧到真实反射上下文（另轮） |

## C. 短耗时真漏报（非超时）

**特征：** 黑→pass，耗时 ≪ 预算（如 168–600ms），或无 allow 名。

| 优先级 | 例子 | 方向 |
|--------|------|------|
| P1 | `url=\/\/evil.com` 反斜杠重定向 | 补 `open-redirect-param` 反斜杠协议相对 |
| P1 | fuzz 异常 CL / 重复 CL（~450ms） | 补/收紧 header 走私规则 |
| P2 | Redis/Mongo/XPath 仍漏 | 查是否被 allow 扣分或 pattern 过窄 |
| P2 | 缓存投毒 / WS / HTTP2 | 协议层规则覆盖 |

## 建议执行顺序

1. A 抬预算 → 重跑看剩余失败数  
2. B P0 allow 收紧 + 样本  
3. B P1 FP 收紧 + 样本  
4. C 按剩余失败补检

本轮代码改动对应：**A + B P0/P1 主干**；C 抽样反斜杠重定向。
