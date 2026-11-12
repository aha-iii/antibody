# Arc-Cortex Console 前端页面

源码：`apps/dashboard/src/pages/`

| 页面 | 文件 | 用途 |
|------|------|------|
| 引擎概览 | `EnginePage.tsx` | Pack 版本、健康、重载 |
| 试打台 | `InspectWorkbench.tsx` | 单条请求 inspect · 看 Arc/Cortex 结果 |
| 案例库 | `SamplesPage.tsx` | `packs/*/samples` |
| **拦截率测试** | `BenchPage.tsx` | blazehttp / GoTestWAF · 明细含路径/耗时 |
| 指标 | `MetricsPage.tsx` | `fast_ratio` · Arc/Cortex 延迟 |
| Shadow | `ShadowPage.tsx` | 异步 Cortex 采样 · 误报反馈 |
| 配置 | `ConfigPages.tsx` | Admission L0 · overlay |
| 登录 | `LoginPage.tsx` | `@nerve/ui` 统一登录壳 |

## 开发

```bash
make dashboard          # UI http://127.0.0.1:5178 → API :8790
```

UI 组件库：仓库根 `@nerve/ui`（与 WAF Console 同款）。
