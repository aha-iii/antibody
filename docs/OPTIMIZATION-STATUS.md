# 引擎优化落地清单（P0–P8）

> baseline **1.5.56** · 2026-08-01 batch3：forced_admin 语义收紧、90-allow 扩面、CI MAX_FP=30、decode/eval buffer 复用、route_gate deep_threshold=0.42

> 对应对话方案：表达力 / regex / signals / L2L3 / challenge / artifact / 业务校准  
> baseline **1.5.43** · 2026-07-29


| 级   | 项                         | 状态   | 落点                                                                       |
| --- | ------------------------- | ---- | ------------------------------------------------------------------------ |
| P0  | challenge → WAF Challenge | ✅    | `expert_bridge` + `NERVE_EXPERT_CHALLENGE_AS`                            |
| P0  | 声明式 signals.yaml          | ✅    | `signals/` + `[policy.signals]` + `compute_signals_with_pack`            |
| P0  | OAuth/JWT/代理 allow        | ✅    | `rules/90-allow/`* + jwt `length_gt`                                     |
| P1  | Artifact format 2→3       | ✅    | `ProgramArtifact::MIN_FORMAT` + 迁移                                       |
| P1  | max_field_chars 截断        | ✅    | pipeline + pack.toml `65536`                                             |
| P1  | 规则前置规范                    | ✅    | `docs/RULE-AUTHORING.md`                                                 |
| P1  | 缓存键含 format               | ✅    | `{pack}-{ver}-{level}-f{FORMAT}.json`                                    |
| P2  | XML/SOAP 轻量拆参             | ✅    | `pipeline/structural/xml.rs`                                             |
| P2  | IP/Geo/Rate 边界            | ✅    | `docs/BOUNDARY-IP-GEO-RATE.md`                                           |
| P3  | semantic-pack 扩面 + FP 文档  | ✅    | `semantic/signatures.yaml` + `FALSE_POSITIVES.md`                        |
| P4  | Hyperscan 就绪              | ✅    | `docs/HYPERSCAN.md` + `scripts/build-with-hyperscan.sh`（真 FFI 需系统 libhs） |
| P5  | challenge/observe 指标      | ✅    | `nerve_native_inspect_{block,challenge,observe}_total`                   |
| P6  | Shadow FP → allow 草稿      | ✅    | `shadow::export_rule_drafts`                                             |
| P7  | pack+format 缓存            | ✅    | 同 P1 缓存键                                                                 |
| P8  | ENGINE / 商业清单同步           | ✅    | `ENGINE.md` + `COMMERCIAL-READINESS.md`                                  |
| P9  | Engram L3 挂钩说明            | ✅ 文档 | `docs/ENGRAM-L3-HOOK.md`（代码未接远端）                                         |


## 部署注意

1. 重载 / 重编 baseline pack（清除旧 `*-f2.json` 缓存或让引擎自动重编 `f3`）
2. 确认 `NERVE_NATIVE_DEV_PACK=1`（明文）或使用 sealed + License
3. Challenge：确认 Edge/事件路径处理 `WafAction::Challenge`（已有 challenge 模块）
4. Hyperscan：镜像装 lib 后 `bash scripts/build-with-hyperscan.sh`

## 非目标（明确不做）

- 完整 ModSecurity SecLang / CRS 1:1
- L3 裸拦
- 引擎内 IP/Geo/滑动窗口限流