# Baseline Samples

与规则文件一一对应：

```text
rules/<category>/<rule_id>.yaml
samples/<category>/<rule_id>.yaml
```

每个样本文件是 YAML 列表。同一规则至少包含：

| 类型 | `expect_action` | 说明 |
|------|-----------------|------|
| 正样本 | `block` / `observe`（检测）或 `pass`（allow） | 应命中该规则语义 |
| 负样本 | `pass` | 干净请求，不应误报 |

本目录**不会**被 `NativePack` 当作规则加载（只读 `rules/`）。

## 工具

```bash
# 按规则拆分旧的扁平 samples/*.yaml
python3 packs/baseline/tools/split_samples_by_rule.py

# 为缺正/负样本的规则自动补齐（保留已有条目）
python3 packs/baseline/tools/ensure_rule_samples.py
```

自动生成的 id 形如 `sample-<rule_id>-gen-block` / `sample-<rule_id>-matched-block`。

## 回归

```bash
# WSL
cd Nerve-waf/Nerve-antibody
cargo build -p nerve-antibody-bench --bin nerve-antibody-samples-regress --release
LEVEL=medium PACK=packs/baseline NERVE_NATIVE_DEV_PACK=1 \
  ./target/release/nerve-antibody-samples-regress
# 报告：packs/baseline/samples-regression-report.txt
```

`expect=block` 时引擎返回 `block` 或 `challenge` 均视为正样本命中。


## 格式

```yaml
- id: sample-sqli-union-select
  rule_id: sqli-union-select
  name: SQL UNION SELECT
  category: 01-sqli
  expect_action: block   # block | observe | pass
  min_level: low
  severity: high
  tags: [sqli]
  request:
    method: GET
    host: example.com
    uri: /api/item
    query: "q=1' union select null--"
    headers:
      User-Agent: nerve-sample/1.0
    body: ""
```
