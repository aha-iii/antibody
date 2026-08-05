# Nerve WAF 商业级指标对标表

> 按商业 WAF 常见 SLA 口径整理。分三档：**云 WAF 轻量**、**企业 CRS 标准**、**深检 Expert**（Nerve 当前主路径）。档位不同，延迟不可直接横比。
>
> 生产验收：`mode=auto` + Expert Fast；bench 脚本默认 `deep` 模式，勿直接签生产 P99。
>
> 关联：[COMMERCIAL-READINESS.md](./COMMERCIAL-READINESS.md) · [ENGINE.md](./ENGINE.md)

---

## 一、延迟性能（WAF 相对「直连后端」的额外耗时）

| 指标 | 商业级目标 | 云 WAF 参考 | 企业 CRS 参考 | Nerve SLO（要达成） | 当前状态（e3c867f1 后 + JSON Fast 优化） | 差距 / 动作 |
|------|-----------|------------|--------------|-------------------|----------------------------------------|------------|
| 引擎快路径（Fast）P50 | +5～20ms | Cloudflare/AWS 托管规则 | — | **≤20ms** | ~30～80ms → 目标 ≤50ms（JSON 快通道后） | Hyperscan、减重复 decode、Pack 预热 |
| 引擎快路径 P99 | ≤50ms | 同左 | — | **≤80ms** | 曾误升 Deep 到 2s+（已修） | 监控 `fast_pool_escalate≈0` |
| 引擎深路径（Deep）P50 | — | — | +30～100ms | **≤100ms** | ~200～500ms（bench deep） | lazy decode、cluster 裁剪 |
| 引擎深路径 P99 | — | — | ≤200ms | **≤300ms** | 最高 ~1.2s（budget 上限） | 压 `max_inspect_ms`、提 Fast 命中率 |
| Expert 全开 · JSON API | — | — | +50～150ms | **≤150ms P95** | 预期 50～150ms（JSON 不再深扫） | 部署新镜像后实测 |
| Expert+Core 全开 · JSON API | — | — | +80～200ms | **≤250ms P95** | 未封板 | Core 开时再测 |
| 首请求冷启动 | ≤100ms 增量 | 边缘预热 | ≤300ms | **≤500ms** | Pack 加载可能 300～800ms | 启动预热 `ensure_engine()` |
| 全链路（含 nginx→edge→后端） | +10～30ms（边缘） | CDN 同源 | +50～150ms（串联） | **≤200ms P95** | 关检测 ~80ms；开 Expert 曾 2s+ | 串联架构天然多 1 跳 |
| Fast 误升 Deep 率 | 0% | — | — | **<0.1%** | 修前几乎 100%（25ms 超时） | 已改 100ms 超时 + 单次 plan |
| Fast 路径占比（干净 API 流量） | ≥90% | — | — | **≥85%** | bench 曾 0%（全 Deep） | JSON clean lane + route_gate |
| budget_exhausted 率 | <1% | — | — | **<1%** | bench 约 6%（49/822） | 提 `max_regex_evals` 或 Fast 分流 |

### 2026-07 性能优化一轮（对标云 WAF L0–L2）

| 项 | 实现 |
|----|------|
| API 正向快通道 | `is_api_positive_lane()`：`/open/api/*`、`/api/*` + JSON POST → 仅 L1 Aho + allow |
| 内联快通道 | `inline_fast_lane`：同步 Fast，禁用线程池（`NERVE_NATIVE_EDGE_INLINE=1`） |
| Deep 预算封顶 | `NERVE_NATIVE_MAX_INSPECT_MS=300`（Edge 默认） |
| 误升 Deep | Fast 超时不再 Deep；Shadow Deep 异步（`NERVE_NATIVE_SHADOW_DEEP=1`） |
| Hyperscan | 打包默认 `--features nerve-waf-expert/accel-hyperscan` |
| Edge 分段日志 | `edge request timing` + `NERVE_EDGE_TIMING_ALL` |

环境变量见 `deploy/mars-test/.env.example`。

### 根因与已修项（2026-07）

| 问题 | 影响 | 修复 |
|------|------|------|
| Edge 每请求重编译 CRS | +500ms～5s | `PreparedSiteInspect` + `SiteInspectCache` |
| Fast 池 25ms 超时 | 几乎 100% 升 Deep | `fast_timeout_ms=100` |
| JSON quote 误判 suspicious | Fast 仍跑全量 regex | `is_clean_json_api` + JSON 跳过 quote 启发 |
| engine 预览 + worker 双 plan | 2× `build_views` | `InspectPlan` 单次规划 |
| 签名/API plausibility | 大量误拦 | `text_plausibility` 修复 |

---

## 二、检出效果（安全能力）

| 指标 | 商业级目标 | Imperva/F5 级 | 云 WAF 托管 | Nerve baseline 实测 | Nerve SLO（要达成） | 差距 / 动作 |
|------|-----------|--------------|------------|-------------------|-------------------|------------|
| GoTestWAF 检出率 | ≥99% | 99%+ | 95～98% | **98.68%**（672/681） | **≥99.5%** | 补 9 条漏报规则 |
| GoTestWAF 误报率 | ≤1% | ≤1% | 2～5% | **2.84%**（4/141） | **≤1%** | FP 闭环 + allow 规则 |
| GoTestWAF 综合准确率 | ≥99% | — | — | **98.42%** | **≥99%** | 同上 |
| blazehttp 全量准确率 | ≥99% | — | — | **92.03%**（历史报告） | **≥99%** | allow + 收紧宽规则；`run-tri-bench-gate.sh` |
| WAFTester 综合准确率 | ≥99% | — | — | **~78.83%**（medium+预算） | **≥99%** | bench deep+1200ms；补协议/JWT/XPath 规则 |
| OWASP CRS 覆盖 | Core Rules Set 完整 | 完整 CRS 3.x | 子集 | baseline 360 条 | 对齐 CRS 3.3 核心 | 持续跟 CRS 版本 |
| blazehttp 白样本误报 | 0 block | 接近 0 | 允许少量 | 207 条登记 FP | **≤20 条** | FALSE_POSITIVES.md 持续收敛 |
| 编码绕过（双重 URL/B64） | 支持 | 支持 | 部分 | 支持（decode 管线） | 保持 | — |
| API 签名误报（sign/tenantCode） | 不误拦 | — | — | 修前大量误拦 | **0 误拦** | 已修 plausibility |
| challenge 误当 block | 可配置 | 支持 | 支持 | Edge 默认 block | API 可 observe | `NERVE_EXPERT_CHALLENGE_AS=log` |
| Shadow 深扫 FP 闭环 | 有 | 有 | 部分 | 已支持 feedback | 生产启用 | Console 误报标注 |

---

## 三、吞吐与稳定性

| 指标 | 商业级目标 | Nerve SLO | 当前 | 动作 |
|------|-----------|-----------|------|------|
| 并发 80 · 错误率 | 0% | 0% | GoTestWAF 0% | 保持 |
| 并发 80 · 平均检测耗时 | ≤50ms | ≤80ms | bench ~510ms（全 Deep） | 生产 auto 模式压测 |
| QPS（单 Edge 核） | ≥5000（轻规则） | ≥2000（Expert Fast） | 未封板 | `run-baseline-conc80.sh` |
| 规则热更新 | 无中断 | 无中断 | 支持 reload | — |
| Expert Pack 加载 | ≤3s | ≤5s | ~8～15s（360 规则×3 档） | IR 缓存 `load_pack_with_cache` |

---

## 四、分模块延迟预算（商业级拆解）

目标：全链路增量拆到可验收的单项（生产 auto + Expert Fast 场景）。

| 模块 | 商业级增量 | Nerve SLO | 说明 |
|------|-----------|-----------|------|
| nginx 转发 | +1～3ms | ≤5ms | OpenResty 剥头 |
| Edge 路由匹配 | +0.5～2ms | ≤3ms | 内存 snapshot |
| Expert 引擎 Fast | +5～20ms | **≤20ms P50** | 目标档位；JSON 快通道后 ≤50ms |
| Expert 引擎 Deep | +30～100ms | ≤100ms P50 | 仅可疑流量 |
| CRS/Core 段 | +20～50ms | ≤80ms | 与 Expert 叠加 |
| 事件写 PostgreSQL | 异步，0 阻塞 | 异步 | 同步写会拖 P99 |
| Edge→后端代理 | +1～5ms | ≤10ms | 网络 RTT 另计 |

**全链路目标**

- Expert Fast · 干净 JSON API：**+15～50ms**（商业可接受）
- Expert+Core · 深检：**+80～200ms**

---

## 五、验收命令

```bash
# 引擎 JSON API 快路径（单元 + 延迟）
cd Nerve-waf-native
NERVE_NATIVE_DEV_PACK=1 cargo test -p nerve-antibody-engine openapi_sms_json -- --nocapture

# Edge 全链路（需 stack 已起）
bash Nerve-waf/scripts/bench-edge-latency.sh

# GoTestWAF baseline（deep 模式，勿签生产 Fast SLO）
bash Nerve-waf-native/scripts/run-baseline-gotestwaf.sh

# 三门禁：gotestwaf + blazehttp + waftester 准确率均 ≥99%（默认 high + deep bench 预算 1200ms）
bash Nerve-waf/Nerve-antibody/scripts/run-tri-bench-gate.sh
MIN_ACCURACY=99 CONCURRENCY=40 bash Nerve-waf/Nerve-antibody/scripts/run-tri-bench-gate.sh
```

### 生产监控指标

| 指标 | 目标 |
|------|------|
| `inspect_fast_ratio` | ≥ 0.85 |
| `fast_pool_escalate` | ≈ 0 |
| `budget_exhausted_total` 增量率 | < 1% |
| `route_gate_deep_ratio` | 与攻击流量比例一致 |

---

## 六、版本对照

| 镜像 / 提交 | 内容 |
|------------|------|
| e3c867f1 | Fast 池 100ms + views 复用 + plausibility |
| 本轮 | `InspectPlan` 单次规划 + JSON clean lane + suspicious 修复 |

部署：`docker load` 后必须 `docker compose up -d --force-recreate`，否则容器仍绑旧 Image。
