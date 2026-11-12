# bench 报告与回归集

本目录存放**本地 bench 产物**，全部位于 `.gitignore`，不随仓库分发。

## 全量 blazehttp

用仓库内的 HTTP 适配器起服务，再用 blazehttp 打：

```bash
cargo run -p nerve-antibody-bench          # 默认 127.0.0.1:8808
/path/to/blazehttp -t http://127.0.0.1:8808 -c 20
```

Dashboard「拦截率测试」页会写出同样的报告：

- `blazehttp-report-<stamp>.json` — 全量用例明细
- `blazehttp-fp-fn-<stamp>.md` — FP/FN 摘要
- 全量跑完后自动写入 `blazehttp-regression-latest.json`（Dashboard 内嵌 bench）

## 从已有报告生成回归集（无需重跑全量）

报告生成器属内部工具，未随仓库发布。仓库内的等价能力是 Dashboard 的
「拦截率测试 → 数据源：blazehttp 回归（仅 FP/FN）」，或直接调用其 API（见下）。

产出（均在 `data/bench/`，gitignore，勿提交）：

- `blazehttp-regression-latest.json` — 仅 FP/FN 用例 id + 元数据
- `blazehttp-analysis-<stamp>.md` — 问题分类与修复建议

## 只测 FP/FN（快速回归）

Dashboard → 拦截率测试 → 数据源 **blazehttp 回归（仅 FP/FN）**

或 API：

```bash
curl -X POST http://127.0.0.1:8790/api/bench/start \
  -H 'Content-Type: application/json' \
  -d '{"dataset":"blazehttp-regression","level":"medium","concurrency":40}'
```

## 指标含义

| 类型 | 条件 | 处理 |
|------|------|------|
| **FN** | black + actual=pass | 补规则 / 降阈值 / 修 decode |
| **FP** | white + actual=block | 收紧规则 / 90-allow / min_level |

详细 FP 治理见 [`packs/baseline/FALSE_POSITIVES.md`](../../packs/baseline/FALSE_POSITIVES.md)。
