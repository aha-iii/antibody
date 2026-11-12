# Native 规则资产：哪里能搞到「全量」？

## 结论（先看这个）

| 想要什么 | 去哪拿 | 在本仓库怎么用 |
|----------|--------|----------------|
| **开源全量签名** | [OWASP CRS](https://github.com/coreruleset/coreruleset)（Apache-2.0） | **已翻译**进 `packs/community-crs/`（Nerve YAML，非直接跑 .conf） |
| **自研高信号尖刀** | 安全运营自写 | `packs/baseline/` |
| **云厂商万级私有库** | 不公开 | 买不到 dump |

**禁止**：把 CRS `.conf` / Coraza 运行时直接当「Nerve Native 引擎」。  
**正确**：用 CRS 导入工具翻译为 Native 规则包，保留 `LICENSE`/`NOTICE`。
翻译工具属 WAF 侧实现，不在本仓库发布；本仓库只存放翻译产物。

---

## 1. `packs/community-crs`（推荐默认）

- 来源：`Nerve-waf/vendor/coreruleset` → `nerve-waf-crs-import`（可导入的 `@rx` 子集）→ Native YAML  
- 约 **219** 条（paranoia≤4；跳过 libinjection/`TX:`/无法映射的 chain 等）  
- 协议：Apache-2.0 衍生作品，见包内 `NOTICE`

```bash
# 在 Nerve-waf 仓库导出 CRS JSON（导入工具属 WAF 侧）
cd Nerve-waf
cargo run -p nerve-waf-crs-import -- \
  --crs-dir vendor/coreruleset \
  --out-dir ../Nerve-antibody/.crs-json-tmp \
  --version 4.25.0 --paranoia-max 4 --clean
```

`packs/community-crs/` 已包含上述流程的产物，常规使用与升级无需重跑。

`nerve-waf-inspect` 默认优先加载 `community-crs`。

---

## 2. 与 Coraza/WASM 的关系

| 路径 | 角色 |
|------|------|
| `packs/community-crs` | Native 引擎主路径（翻译后的自有格式） |
| Coraza/WASM + vendor CRS | 仅作 `NERVE_NATIVE_ENGINE=off` 或引擎未加载时的**回退** |

---

## 3. 不能翻译进去的 CRS 部分

- `@detectSQLi` / `@detectXSS`（libinjection，无正则）  
- 依赖 `TX:` 变量、异常评分相位的规则  
- 无法映射到 Native DSL 的复杂 chain  

这些若需要，仍走语义引擎 / 专用检测，或继续改进 DSL 后再导入。

---

## 4. 包对照

| 包 | 定位 | 条数 |
|----|------|------|
| `community-crs` | CRS 翻译全量（可导入子集） | ~219 |
| `baseline` | 自研高信号 + blazehttp 漏报补全（1.1.0）；`rules/<类>/<id>.yaml` | ~217 |
| `baseline/false-positives.yaml` | blazehttp 白样本误报登记 | 207 |
| `baseline/samples` | 每规则 ≥1 试打案例（Dashboard 案例库） | ~300+（含 alt / gap） |
| `demo` | 单测 | ~4 |

再生 / 拆分 baseline 案例（按规则文件）：`python3 packs/baseline/tools/split_samples_by_rule.py`
