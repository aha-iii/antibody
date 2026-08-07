# Native Engine 商业化就绪清单

> 对应平台架构 spec P0–P2；引擎仓库 `Nerve-waf-native/`。  
> **SLO 对标表**：[COMMERCIAL-SLO.md](./COMMERCIAL-SLO.md)

## P0 — 准确率 vs 性能（最大风险）

| 项 | 状态 | 说明 |
|----|------|------|
| 双路径 inspect | **已落地** | Stage-0 `route_gate` 线性特征路由 + 快路径 `for_fast_path()` 轻量 pipeline |
| Bench 与生产分离 | **已落地** | Dashboard bench 自动设 `NERVE_NATIVE_INSPECT_MODE=deep` |
| 分阶段 metrics | **已落地** | decode / aho / regex / semantic / fusion 各阶段 `*_us_avg` |
| Fusion v3 | **已落地（可选）** | `[policy.fusion].min_independent_signals`；弱信号 block 降级 challenge |
| semantic-pack v2 | **已落地** | `match: token_seq` 原语 + regex `pattern` |
| 高并发 budget 熔断可观测 | **已落地** | `nerve_native_budget_exhausted_*` + `budget_exhausted` 字段 |
| high 99.99% / conc=80 稳定 | **进行中** | 脚本 `scripts/run-baseline-conc80.sh` 封板；双池超时改 deep 降级 |
| 路由权重校准 | **已落地** | 20 维 Learned Fast Filter + `config/route_weights.json`；`scripts/calibrate_route_gate.py` |
| Fast 池超时策略 | **已落地** | 25ms 超时 → deep 池（`fast_pool_escalate` 指标） |
| 分阶段 metrics 调参 | **已落地** | `scripts/analyze_stage_metrics.py`；bench report 含 `engine_metrics` |
| challenge → WAF Challenge | **已落地** | `expert_bridge` 映射；`NERVE_EXPERT_CHALLENGE_AS=challenge\|log\|block` |
| 声明式 signals.yaml | **已落地** | `[policy.signals]` + `signals/signals.yaml`；feature/fingerprint 可扩 |
| OAuth/JWT/代理头 allow | **已落地** | baseline `90-allow` + length/feature 门闩（见 FALSE_POSITIVES） |

### P1 算法/架构（本轮）

| 项 | 状态 |
|----|------|
| Learned Fast Filter | **已落地** | 20 维特征 + pack/JSON 权重 |
| 深路径 field cluster | **已落地** | fast/deep 均 cluster 裁剪 + suspicious fallback |
| Lazy decode 层间早退 | **已落地** | `inspect_lazy_layers` 逐层 decode+match |
| SQLi 轻量 lexer | **已落地** | `sqli_lexer` 辅助 union/tautology |
| Console FP 闭环 | **已落地** | `POST /api/shadow/feedback` + `GET /api/shadow/export-rules`（allow 草稿含 feature/fingerprint 占位 + matched `rule_id`） |
| Artifact format 2→3 | **已落地** | 加载兼容迁移；写出 format=3 |
| `max_field_chars` 字段截断 | **已落地** | pipeline 默认 65536；pack 可配 |
| 规则编写指南 | **已落地** | [RULE-AUTHORING.md](./RULE-AUTHORING.md) |
| IP/Geo/rate 边界文档 | **已落地** | [BOUNDARY-IP-GEO-RATE.md](./BOUNDARY-IP-GEO-RATE.md) |
| Hyperscan 真链接 | **入口就绪** | FFI + [HYPERSCAN.md](./HYPERSCAN.md)；无 libhs 时回退 RegexSet |

### P1+ 架构增强（历史）

| 项 | 状态 |
|----|------|
| 规则视图簇编译 | **已落地** | `FieldClusters` + 快路径 cluster 裁剪 |
| Lazy decode 两阶段 | **已落地** | 浅层 depth≤2 优先，可疑再全量 |
| Fast/Deep 双 worker 池 | **已落地** | `NERVE_NATIVE_INSPECT_POOL=1`（默认开） |
| Shadow deep | **已落地** | 快路径异步深扫；`/api/shadow/recent`（含 `rule_id`） |
| Hyperscan FFI feature | **已落地入口** | `accel-hyperscan-ffi`；无 libhs 时回退 RegexSet |
| length/feature/fingerprint 谓词 | **已落地** | DSL + runtime 廉价路径 |
| 嵌套 when | **已落地** | compiler/runtime Group 节点 |

**运维建议**

- 生产：保持 `mode=auto`，监控 `inspect_fast_ratio` ≥ 0.85（干净流量场景）
- 压测/验收：bench 或显式 `deep`，勿用 bench 数字直接签生产 P99 SLO
- 高 QPS：增大 worker 隔离或降 `max_inspect_ms` 快路径 cap，避免全员深扫
- challenge：默认保留 WAF Challenge；兼容旧面板可设 `NERVE_EXPERT_CHALLENGE_AS=log`

## P1 — L2 语义层可扩展

| 项 | 状态 | 说明 |
|----|------|------|
| semantic-pack YAML | **已落地** | `pack.toml` → `[policy.semantic].pack_path`；baseline 见 `semantic/signatures.yaml` |
| 热更 | **已落地** | `Engine::reload` 重载语义包；签名与内置 analyzers 叠加 |
| L1/L2 归因 | **部分** | 命中 `rule_id` vs `pack.<sig_id>` / `sqli.*` 语义 id 分离；TopN 指标见 `/metrics` |

**边界**

- L2 仍不单独 block（Fusion）；`block_eligible` 语义信号需 L1/解码佐证
- 新攻击面优先加 semantic-pack 或 L1 规则，减少改 Rust 发版频率
- IP/Geo/rate **不进** L1（见边界文档）

## P1 — L3 / AI 话术克制

| 项 | 状态 | 说明 |
|----|------|------|
| Fusion 禁裸模型 block | **已有** | adaptive 仅加分/佐证 |
| ONNX / Linear | **feature 入口** | 默认启发式；勿对外称「AI 引擎已全面拦截」 |
| Engram-Detect 打通 | **未做** | 平台 Intelligent 柱后续项 |

**对外表述**

- 可说：「自适应风险分（L3）辅助 Fusion，可接 ONNX」
- 不宜说：「AI 驱动全自动阻断」直至 Engram 与线上 shadow 证据齐全

## P2 — Runtime Observability

| 指标 | 端点 | 说明 |
|------|------|------|
| inspect 总量 / 快深分流 | `GET /metrics` | `nerve_native_inspect_{fast,deep}_total`、`*_ratio` |
| 延迟分位（桶） | `GET /metrics` | `nerve_native_inspect_latency_bucket{le=...}` |
| budget_exhausted 率 | `GET /metrics` | `nerve_native_budget_exhausted_ratio` |
| rule_id TopN | `GET /metrics` / `/api/metrics` | `nerve_native_rule_hits_total{rule_id=...}` |
| JSON 快照 | `GET /api/metrics` | Dashboard 调试 |
| Shadow FP 导出 | `GET /api/shadow/export-rules` | allow YAML 草稿 |

**签 SLO 最小集**

1. 快路径 P99 ≤ 20ms（`le_20ms` 桶占比）
2. `budget_exhausted_ratio` < 1%（正常负载）
3. bench deep 模式检出率与生产 auto 分流比一并报告

## 验证命令

```bash
cd Nerve-waf/Nerve-antibody   # WSL: /mnt/d/workspace/waf/Nerve-waf/Nerve-antibody
cargo test -p nerve-antibody-runtime route_gate
# 校准 route_gate（合成样本；有 bench 报告时加 --input）
python3 scripts/calibrate_route_gate.py \
  --out-weights packs/baseline/config/route_weights.json
# 可选：用 Dashboard 导出的 bench JSON
# python3 scripts/calibrate_route_gate.py -i /tmp/bench-report.json -o packs/baseline/config/route_weights.json
# 将打印的 deep_threshold 写回 pack.toml [policy.inspect.route_gate]
cargo run -p nerve-antibody-dashboard
curl -s http://127.0.0.1:8790/api/health | jq .inspect_mode
```

**Nerve RIS / route_gate 边界**：只决定 Arc(fast)/Cortex(deep) 与 `ris_zone`，**不参与 block 定罪**。验收：攻击集 auto 检出 ≥95%；干净流量 fast_ratio ≥85%。

## 相关文档

- [ENGINE.md](./ENGINE.md) — 能力与技术细节
- [RULE-AUTHORING.md](./RULE-AUTHORING.md) — 规则编写
- [BOUNDARY-IP-GEO-RATE.md](./BOUNDARY-IP-GEO-RATE.md) — IP/Geo/限流边界
- [HYPERSCAN.md](./HYPERSCAN.md) — Hyperscan / Vectorscan
- [平台架构 spec](../../docs/superpowers/specs/2026-07-26-nerve-platform-architecture.md)
