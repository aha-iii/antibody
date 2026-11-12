# contract · 契约层

定义**规则长什么样、包怎么发**，不含在线检测算法。被 `compile/` 读取，被 `packs/` 目录下的 YAML/TOML 实例化。

| Crate | 职责 |
|-------|------|
| **`nerve-antibody-dsl`** | 规则 AST：`when.all/any`、字段（uri/query/body/header…）、谓词（contains/regex/length…）、动作（block/observe/allow）、`min_level`、transforms；YAML/JSON 加载与校验 |
| **`nerve-antibody-pack`** | 规则包 manifest（`pack.toml`）、目录打包与解包、内容 hash、版本号、可选 HMAC 签名与密封发版 |
| **`nerve-antibody-license`** | 客户 license / entitlement 校验，控制哪些 pack 或能力可用 |

```text
packs/baseline/rules/*.yaml  →  dsl::load  →  NativeRule
packs/baseline/pack.toml     →  pack::load  →  PackManifest
```

文档：[`docs/arc-cortex/01-contract/`](../../../docs/arc-cortex/01-contract/)
