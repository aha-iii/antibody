## Expert blazehttp 结果（baseline / medium）

- 时间: 2026-07-24
- 目标: http://127.0.0.1:8808 (nerve-antibody-bench)
- 规则包: packs/baseline
- 引擎级别: medium
- 并发: 40

| 指标 | 数值 |
|---|---|
| 总样本 | 33877（成功 33877，错误 0）|
| 检出率 | **0.46%**（恶意 658，拦截 3，漏报 655）|
| 误报率 | **0.00%**（正常 33219，放行 33218，误拦 1）|
| 准确率 | 98.06% |
| 平均耗时 | 263.93 ms |

原始输出: /tmp/blazehttp-expert-baseline-result.txt（WSL）

说明: baseline 是精简专家包（约 184 条），不是完整 CRS；blazehttp 恶意集覆盖面远大于当前规则面，故检出率低、误报极低属预期。若要对齐雷池公开数字，需换 community-crs / 更高覆盖规则包，或对标完整 WAF 网关链路。
