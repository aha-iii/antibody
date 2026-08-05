# Native L1 规则编写指南

> 适用：`packs/*/rules/**/*.yaml`、声明式 `signals/signals.yaml`  
> 引擎：`nerve-antibody-engine`（谓词见 DSL：`contains` / `regex` / `length_gt` / `length_lt` / `feature` / `fingerprint`）

本文约定如何写 **可维护、便宜、少误报** 的 L1 规则。IP / Geo / 限流边界见 [BOUNDARY-IP-GEO-RATE.md](./BOUNDARY-IP-GEO-RATE.md)。

---

## 0. 规则说明 `doc`

**约定**：规则说明以 YAML 内可选 **`doc` 块为唯一数据源**（Dashboard 展示与检索均读此字段）；文件顶一行 `#` 摘要**可选**，仅作编辑器/ diff 速览，须与 `doc.summary` 一致，**不要**在 `#` 里写长说明或重复 block/pass 示例。

| 字段 | 必填 | 说明 |
|------|------|------|
| `summary` | 是 | 一句话：这条规则做什么 |
| `detects` | 否 | 检测面、scope、transforms、动作等要点（多行 `\|`） |
| `block_examples` | 否 | 应拦截/命中的请求示例（字符串列表） |
| `pass_examples` | 否 | 应放行的边界用例（误报对照） |
| `notes` | 否 | 可选：协议约束、兼容坑、门闩边界（不写评测集编号、变更历史、FP 排查记录） |

```yaml
# 开放重定向：检测 next/url 等参数指向外站
doc:
  summary: 检测常见开放重定向参数指向外部 HTTP(S) URL。
  detects: |
    query/body/uri 顶层 raw 串；scope: raw；transforms: url_decode_uni, lowercase。
  block_examples:
    - GET /login?next=https://evil.example/phish
  pass_examples:
    - GET /search?q=url=http://benign.example
id: open-redirect-param
name: ...
```

旧规则无 `doc` 仍可加载。新规则 / 大改规则应补全 `doc`；baseline 以 `open-redirect-param.yaml` 为模板试点，再按规则集目录分批覆盖其余规则。

---

## 1. 谓词优先级：便宜优先

匹配成本大致为：

| 优先 | 谓词 | 说明 |
|------|------|------|
| 1 | `feature:` / `fingerprint:` | 预计算布尔；热路径几乎免费 |
| 2 | `contains` | 字面量；可进 Aho / 字典预过滤 |
| 3 | `length_gt` / `length_lt` | O(1) 字段长度门闩 |
| 4 | `regex` | 最贵；受 `max_regex_evals` 预算约束 |

**推荐**：先用 feature / contains / length 把门闩卡住，再把 regex 放进同一 `when.all` 的后段（见下节）。避免「整包 body 上一条裸 regex」作为唯一条件。

```yaml
# 好：便宜门闩 + 昂贵确认
when:
  all:
    - field: body
      length_gt: 64
    - field: body
      contains: "union"
    - field: body
      regex: '(?i)union\s+select'

# 差：一上来全量 regex
when:
  all:
    - field: body
      regex: '(?i).{0,200}union\s+select'
```

---

## 2. 嵌套 `when.all`：便宜 + 昂贵

`when.all` / `when.any` 可嵌套。语义上 **`all` 即链式确认**（不必另发明 CRS 式 `chain`）。

写法约定：

1. **外层 `any`**：多条攻击变体 / 多字段入口  
2. **内层 `all`**：同一变体上「门闩 ∧ 确认」  
3. **门闩在前**：`feature` → `length_*` / `contains` → `regex`

```yaml
when:
  any:
    - all:
        - feature: long_authorization
        - field: header
          header_name: Authorization
          contains: "eyJ"
        - field: header
          header_name: Authorization
          regex: '(?i)Bearer\s+eyJ[A-Za-z0-9_-]{20,}\.'
    - all:
        - field: query
          length_gt: 4096
        - field: query
          contains: "access_token=eyJ"
```

编译与运行时仍按规则求值；门闩失败可避免无意义的 regex 与证据膨胀。预算紧张时，裸 regex 规则最先被熔断伤害。

---

## 3. 字段匹配范围 `scope`

| 值 | 含义 |
|----|------|
| `all`（默认） | 整段 `query`/`body`/`uri` + 拆参切片（`query.q`）+ 解码视图 |
| `raw` | **仅**顶层字段串（`req.query` / `req.body` / `req.uri`），不扫 `query.{name}` 参数值 |

开放重定向等「看 HTTP 参数名是否为 `next`/`redirect_uri`」的规则应使用 `scope: raw`，避免 `?q=url=http://...` 类正文误报。

```yaml
- field: query
  scope: raw
  regex: '(?i)(?:^|&)(?:next|redirect_uri)=https?://'
```

---

## 4. 声明式 `signals.yaml`

路径（pack 内，引擎按序尝试）：

- `signals/signals.yaml`（baseline 默认）
- 或 `signals.yaml` / `pack.toml` 中声明的相对路径

格式概要：

```yaml
version: "1.0.0"

features:
  - name: long_query
    kind: length_gt
    target: query
    threshold: 512
  - name: has_x_forwarded_for
    kind: header_present
    header: x-forwarded-for
  - name: body_has_client_id
    kind: body_contains
    value: client_id=

fingerprints:
  - name: oauth_authorize_path
    kind: path_prefix
    prefix: /oauth/authorize
```

规则侧引用（无需再写一遍探测逻辑）：

```yaml
when:
  all:
    - feature: long_query
    - fingerprint: oauth_authorize_path
```

**何时加 signal、何时写规则**

| 场景 | 放哪里 |
|------|--------|
| 可复用的头/路径/长度/字面标记 | `signals.yaml` → `feature` / `fingerprint` |
| 攻击语义确认（contains/regex + score/action） | `rules/**/*.yaml` |
| 业务放行指纹 | signal + `action: allow` 规则组合 |

Signal 与内置 feature/fingerprint **叠加**；同名以包内定义为准时以加载实现为准，新增名称时避免与内置冲突。

---

## 4. `allow` 规则治理误报（FP）

- `action: allow`：命中后按 **负分豁免** 参与评分（见 runtime：allow 分从攻击分中扣除）
- 放在 `rules/90-allow/`（或同等低优先级目录），`tags` 含 `fp` 便于审计
- **必须带窄门闩**（feature / fingerprint / 路径前缀），禁止「contains 一个常见词就 allow」

```yaml
id: oauth-token-exchange-allow
action: allow
score: 40
tags: [fp, oauth]
when:
  any:
    - all:
        - feature: oauth_token_exchange
        - fingerprint: keycloak_token_path
```

流程建议：Shadow / 反馈标 FP → 导出 allow 草稿 → 人工收紧门闩 → 合入 pack → `Engine::reload`。

---

## 5. 禁止写入 L1 的内容

**不要**在 native L1 规则里实现或模拟：

| 能力 | 归属 |
|------|------|
| IP deny / 黑白名单 | Edge / Control（deny_ip 等） |
| Geo 国家/地区 | Edge / Control GeoIP |
| 连接/请求速率限流 | Edge / APISIX / rate-limit 策略 |

原因：热路径是签名与异常分，不是准入与配额；在 regex 引擎里做滑动窗口或 Geo 库会拖垮 P99，并越界产品分层。

若业务需要「边缘已判定超限后再加强检测」，由 Edge **注入可信头**，再在 `signals.yaml` 声明 `feature`（见边界文档「可选未来」）。L1 只消费 feature，不自己算 rate/Geo。

---

## 6. 自检清单

- [ ] 昂贵 `regex` 是否被 `contains` / `length_*` / `feature` 门闩保护？
- [ ] 可复用探测是否进了 `signals.yaml` 而非复制粘贴进多条规则？
- [ ] allow 是否足够窄，不会误放行攻击变体？
- [ ] 是否误把 IP / Geo / rate 写进了 L1？
- [ ] `min_level` / `score` / `action` 与 pack 阈值叙事一致？
