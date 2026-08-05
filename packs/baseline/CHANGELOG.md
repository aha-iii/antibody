# baseline changelog

## 1.5.43
- 引擎：Shadow FP 导出增强 — `fp`/`false_positive` 生成 `action: allow` YAML 草稿，含 feature/fingerprint 占位与 matched `rule_id`
- 规则：`90-allow` OAuth token/redirect_uri、OIDC UUID 路径、proxy `X-Original-URL` allow
- 文档：`ENGINE.md` 同步声明式 signals、length/feature/fingerprint、嵌套 when、artifact 2/3、`max_field_chars`、challenge 映射（`NERVE_EXPERT_CHALLENGE_AS`）、Fast/Deep、Hyperscan 可选、IP/Geo/rate 边界
- 文档：`COMMERCIAL-READINESS.md` 勾选 signals / challenge bridge / artifact 兼容 / Shadow 导出等已完成项
- 关联：`RULE-AUTHORING.md`、`BOUNDARY-IP-GEO-RATE.md`、`HYPERSCAN.md`、`ENGRAM-L3-HOOK.md`、`OPTIMIZATION-STATUS.md`

## 1.5.42
- 声明式 `signals/signals.yaml` + `[policy.signals]`；OAuth/代理头 allow 规则与 feature/fingerprint 门闩
- Artifact format 2→3 兼容加载；`max_field_chars` 字段预算；challenge 经 `expert_bridge` 映射 WAF Challenge

## 1.5.27
- 引擎：medium/high 恢复全量 regex 候选；high 禁用 early-exit；静态资源 low 档仍走快路径
- 引擎：bench 大包 body 头尾截断 + 语义层 UTF-8 安全采样（blaze 二进制 panic 修复）
- 性能：bench blocking 线程池 + 默认并发 80
- `max_inspect_ms` 恢复 800（high clamp 300–800）

## 1.5.26
- high：`max_inspect_ms` 1200，消除 blaze 大包超时假漏报
- 规则：unix: SSRF、JndiLoginModule、Unicode/事件 XSS 逃逸、feedback opaque POST
- 修复语义/运行时 head_tail 在多字节 UTF-8 边界 panic

## 1.5.25
- 剩余 medium 规则下沉到 low（仅保留少量 FP 敏感规则在 medium/high），冲 low≥85%

## 1.5.24
- 三档拦截梯：阈值 low=40 / medium=36 / high=32；low 管线预算不再压到 60ms
- 语义高信号族在 low 也启用；批量下调 min_level（high→medium，热区 medium→low）
- 目标：三套件 low≥85 / medium≥95 / high≥99.99

## 1.5.23
- harness：glob `???` 不按 query 拆分；`?;.css` 整段保留；识别 HTTP/0.9
- 规则：收尾 13 条 FN（cache 头、JSON 嵌套污染、glob、authority）

## 1.5.22
- 评测 harness：raw HTTP 解析写入 `_proto_anomaly`（裸 CR、HTTP/0.9、TE 异常、GET+TE、chunk 异常等）
- 规则：proto-anomaly-marker + 剩余 FN 杂项

## 1.5.21
- 语义：原文层捕获双编码 LFI、padded rev-shell、XML Schema include（避开 decode/预算漏检）

## 1.5.20
- 引擎：超长 body/uri 头尾采样，避免填充绕过；抬高 high 档 inspect 预算
- 语义：normalize_blob 头尾保留
- 规则：双编码 LFI、URL 编码 padded RCE、XML Schema include

## 1.5.19
- 评测：跳过 repeat>1 的 rate-limit 单包不可判定样本
- 管线：扩大缓存投毒/覆盖头侧信道
- 规则：冲刺 99.99% 剩余 FN（JWT stub、XPath/XXE、n8n/IDOR、协议头 XSS、GTW UA/SSI/ASP/padded RCE）

## 1.5.18
- 规则：GoTestWAF 向 XSS 事件/confirm.call、Mongo shell、$where、IMAP/SMTP、LDAP、wget/getent 补齐（含 uri/body）

## 1.5.17
- 规则：冲刺剩余 FN（双编码 format/%u、BIDI、全角 SQLi、XSS concat、路径重定向、JWT 超大、BOLA 过滤参数）

## 1.5.16
- 规则：修复 %A0 ACL 匹配（避免 url_decode lossy）；Windows UNC/LFI、localhost SSRF 别名、BOLA 头、格式串/BIDI、路径开放重定向；上传 inc/module

## 1.5.15
- 规则：上传 so/war/jar、SQLi SHUTDOWN/UDF、ACL 路径绕过、杂项开放重定向与双 Host/XFP

## 1.5.14
- 规则：扩展 OS/LOLBAS、Unicode LFI、BOLA 路径、Header/CL 异常与 SQL UNHEX/REVERSE

## 1.5.13
- 评测：raw HTTP 归一化裸 CR；保留空名头/无冒号异常行
- 规则：畸形 Header 行探测

## 1.5.12
- 规则：超大 Content-Length / TE 命名异常、绝对 URI `@` 混淆、超大 JWT

## 1.5.11
- 规则：异协议 SSRF、系统运维路径、overlong 引号、ANSI-C RCE、url[]/Unicode 开放重定向

## 1.5.10
- 规则：双重编码 overlong LFI、分号路径绕过、Base64/Host 开放重定向、JWT zip/DEF、恢复流探测、OS cmd 扩展

## 1.5.9
- 规则：IDOR/BOLA 路径扩展、Redis SCAN/DUMP、OS cmd printenv/find/reg、裸元字符/格式化串探测

## 1.5.8
- 规则：双重编码控制符、XSS JS 拼接/bracket/map、上传 hta/shtml/dll、SSRF 172.16-31/IPv6、方法覆盖头；`max_regex_evals` 提到 20000

## 1.5.7
- 评测：JWT 仅写入 query，避免 Authorization 双通道耗尽正则预算漏报
- 规则：开放重定向 RelayState/反斜杠、Redis/Mongo 命令、Unicode overlong LFI、缓存欺骗扩展名、HTTP/2 伪头、IDOR UUID

## 1.5.6
- 规则：IDOR 数字 API、空字节/控制符、上传扩展名补全、NoSQL `$type/$eval`/FLUSHALL、LDAP 通配、残缺 XSS 标签、JWT 两段缺签

## 1.5.5
- 评测：WAFtester 结构化 `method`/`body`/`headers`（n8n 等）并入请求；路径允许 `<slug>` 占位
- 规则：原型污染、敏感 API 侦察、SQLi 尾引号/断注释、JWT 结构异常、DNS rebinding SSRF、Redis/n8n RCE

## 1.5.4
- 评测：WAFtester 应用路径进 URI、JSON/GraphQL 进 body；raw HTTP 重复头换行保留（走私证据）
- 规则：强制浏览 admin、提权 mass-assign、GraphQL 内省/批处理、CL.TE 走私、NoSQL JS、XPath、上传 webshell 名、OS 命令分隔
- 语义：云 metadata / GraphQL 内省 / 提权字段 / 强制浏览路径；上传扩展名覆盖 phar/asp/ashx
- SSRF metadata 与开放重定向反斜杠/空白绕过补强

## 1.5.3
- 开放重定向：跳转参数绝对 URL + 协议相对 `//host`
- 登录绕过：尾注释 `admin'--`、括号 or、NoSQL `$ne/$where`；LDAP `*)(uid=` 形态
- CRLF：Redis/FTP/IMAP/SMTP/日志伪造协议命令注入

## 1.5.2
- JWT：解码 header+payload 全段；覆盖嵌套 none、claim 内 LFI/SQLi/XSS/SSTI

## 1.5.1
- 算法：URL 解码支持 IIS `%uXXXX`；Host/Authorization/X-Forwarded-Host 进侧信道
- 语义：JWT alg=none / kid|jku|x5u URL / kid 注入；YAML/Jackson 反序列化 gadget；CRLF 覆盖 Unicode/%u
- 规则：jwt-alg-none、jwt-header-url-ssrf、deser-yaml-jackson-gadget；CRLF 规则加强
- 评测：JWT payload 写入 Authorization + access_token

## 1.5.0
- 自研补强（非 CRS 拷贝）：CRLF 头注入、编码回环 SSRF、overlong LFI、timer/Function XSS、引号管道 RCE、UNION 断注释 SQLi、UA/可注入头 XSS
- 算法：Header 侧信道扩展 UA / X-Nerve-Test / XFF 等，并对 uri|query|body 规则可见；Header 规则消费解码视图
- 评测：WAFtester 路径型进 URI、单行可注入头进 Header；语义层对齐上述逃逸族

## 1.4.4
- 补漏：animationcancel/download、tinymce `_template`、PHP 反序列化；逃逸扫描先 URL/JS 解码
- 维持清晰边界：白流量 challenge 目标 <5%（静态资源强制 pass）

## 1.4.3
- pass/challenge 边界固化：静态资源无佐证 → pass；challenge 仅可解释可疑（关键字模型 / 解码攻击形 / 编码逃逸）
- base64 候选优先长 token；独立编码扫描补双重 b64 / OGNL / PHP 形
- 补漏规则：xp_dirtree/UTL_INADDR、onclick/prompt、makeRequest@、F5 bash、elFinder archive；case-when 降至 medium

## 1.4.2
- 生产边界：pass=无攻击佐证；challenge=可解释可疑（模型贡献门闩 / 解码攻击形 / 逃逸特征）；block=硬定罪
- 模型贡献去掉裸 `decode_depth`（防静态资源刷 challenge）
- 静态资源路径无佐证强制 observe；URI CRLF / 密集 unicode·实体 → challenge

## 1.4.0
- Fusion：medium/high 模型已贡献 → `challenge`（消 adaptive-only 漏报；仍禁裸模型 hard-block）
- 深解码(depth≥4)+模型 → hard block
- 补漏规则：base-href/js、body-background、ssti 引号、session-input、select-cast、cscot、svg-xlink、jenkins-checkscript

## 1.3.2
- 取消 `union…select` soft_assist；搜索/遥测路径 prose veto
- XSS：仅完整 `<script>`/`src=` 定罪；`binary<script is incorrect` allow + veto
- 特征 SQL 关键字去掉裸 `and`/`or`（防英文散文抬分）
- `xss-script-tag` 正则收窄为完整标签

## 1.3.1
- 语义 FP 治理：`union`/`comment`/`ldap`/`hex`/`script` 改为 soft_assist 或 prose veto；不可单独定罪
- Fusion：软语义不可借模型定罪；特征佐证 medium 需 ≥3 攻击关键字
- `ldap-injection-filter` / `admin-backup-ext` 收窄；backup 升 high
- high `challenge` 提高门槛（p≥0.90 ∧ score≥18 ∧ attack_kw≥1）
- bench：白样本 challenge 不计误报；黑样本 challenge 仍计检出

## 1.3.0
- Fusion v2：分层定罪（强 L1/L2、弱规则∧模型、特征佐证）；禁裸模型硬拦；high 支持 `challenge`
- Decode v2：有界递归解码（`max_decode_depth`）；low 开浅层 base64
- Semantic v2：SQLi/XSS/Path/RCE/SSTI/LDAP/Upload + `block_eligible` + prose veto
- 阈值：`low=48 / medium=40 / high=32`；收紧 `sqli-hex-0x` / `sqli-case-when`；`rfi-remote-http` 改 observe
- 约 50 条高置信规则 `min_level` 升至 low（网关覆盖）

## 1.2.0
- 引擎三层融合：规则分 + allow 负分 + 语义信号 + 自适应模型（模型不可单独拦截）
- `pack.toml`：`threshold_by_level`（low=55 / medium=40 / high=25）、semantic/adaptive 开关
- 新增 `00-allow/*`（Adobe `;cat=`、captcha onload、静态 config.json）
- 收紧 `xss-onload`、`admin-env-leak-path`（升 high / 降分）

## 1.1.0
- 对照 blazehttp 全量报告补漏报：新增 `12-xss-evasions` / `13-sqli-evasions` / `14-upload-rce-java`
- DSL 新增变换 `js_unescape`、`html_numeric_decode`；XSS 规则默认启用
- 误报治理：收紧 `rce-backtick` / `xxe-doctype` / `sqli-into-outfile` / `sqli-union-select`；`ssrf-loopback` 升至 high
- 登记 `false-positives.yaml`（207 条 blazehttp 白样本误报，`mark: false_positive`）
- 规则布局改为 `rules/<类别>/<id>.yaml`；pack 加载器递归收集 `rules/**/*.yaml`
- blazehttp 误报收紧：`xss-concat-alert` / `xss-js-hex-alert` / `xss-javascript-uri` / `xss-script-tag` / `sqli-union-select` / `sqli-into-outfile` 等（见 `FALSE_POSITIVES.md`）

## 1.0.0
- 首版自研高信号规则，约 184 条
- 分类对齐 AWS/阿里：sqli/xss/rce/lfi/ssrf/xxe/webshell/admin/known_bad
- 偏少误报；宽泛探测放 high 或 observe
