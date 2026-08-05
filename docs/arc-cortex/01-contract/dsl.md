# nerve-antibody-dsl

规则 **AST** 与加载校验。

## 职责

- `when.all` / `when.any`（可嵌套 `WhenNode::Group`）
- 字段：`uri` · `query` · `body` · `method` · `header` · `response_body` · `feature` · `fingerprint`
- 谓词：`contains` · `regex` · `length_gt/lt` · `feature` · `fingerprint`
- 动作：`block` · `observe` · `allow`（负分豁免）
- 强度：`min_level` → `NativeLevel`（Low / Medium / High）
- 变换：`lowercase` · `url_decode` · `html_entity_decode` 等

## 子模块

| 模块 | 职责 |
|------|------|
| `types` | 规则 AST、条件、整条 `NativeRule` |
| `transforms` | 匹配前字符串变换 |
| `load` | YAML/JSON 文件解析 |
| `error` | DSL 错误 |

## 编写约定

见 [`../../RULE-AUTHORING.md`](../../RULE-AUTHORING.md)。
