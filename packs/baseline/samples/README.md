# Baseline Samples

与 `rules/<类别>/<id>.yaml` 一一对应的试打案例（每条规则 ≥1 个，部分有 alt 字段变体）。

blazehttp 漏报补全试打见 `12-blazehttp-gap.yaml`。误报登记见包根目录 `../false-positives.yaml`。

## 生成

```bash
python3 scripts/gen_baseline_samples.py
```

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
    query: "q=1 union select null--"
    headers:
      User-Agent: nerve-sample/1.0
    body: ""
```

本目录**不会**被 `NativePack` 当作规则加载（只读 `rules/`）。
