# 评测数据集（Dashboard 拦截率页）

进程内 `engine.inspect` 跑表，不依赖外挂二进制打靶（`:8808` 仍可供外部工具）。

| 数据集 ID | 说明 | 拉取 |
|-----------|------|------|
| `samples` | 当前规则包 `packs/<pack>/samples` | 无需 |
| `blazehttp` | 长亭黑/白 raw HTTP | `bash scripts/fetch-blazehttp.sh` |
| `gotestwaf` | Wallarm GoTestWAF YAML | `bash scripts/fetch-gotestwaf.sh` |
| `waftester` | WAFtester `payloads/*.json` | `bash scripts/fetch-waftester.sh` |
| `crs-ftw` | OWASP CRS FTW 回归 | `bash scripts/fetch-crs-ftw.sh` |

一键：

```bash
bash Nerve-waf-native/scripts/fetch-all-datasets.sh
```

默认链到 `/tmp/<name>`，并软链 `Nerve-waf-native/vendor/<name>`。

页面：拦截率测试 → 选择数据集 → 开始 → KPI + 环形图 + TP/FN/TN/FP 条 + 用例明细。
