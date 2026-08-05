# 规则包（packs/）

发版资产，**不是** Rust crate。Arc-Cortex 通过 `nerve-antibody-pack` 加载。

## 包列表

| 目录 | 说明 |
|------|------|
| [`baseline/`](../../../packs/baseline/) | 自研主包（生产默认） |
| [`community-crs/`](../../../packs/community-crs/) | OWASP CRS 翻译 YAML |
| [`demo/`](../../../packs/demo/) | 单测 / 演示 |

来源说明：[`../../../packs/SOURCES.md`](../../../packs/SOURCES.md)

---

## baseline 目录结构

```text
packs/baseline/
├── pack.toml              # 策略：inspect.mode、route_gate、预算、fast_lanes
├── CHANGELOG.md
├── FALSE_POSITIVES.md     # 已知误报登记
├── signals.yaml           # Arc/Cortex 路由 hints（若存在）
├── semantic/
│   └── signatures.yaml    # L2 语义签名
├── samples/               # Dashboard 案例库（gen 脚本生成）
└── rules/
    ├── 01-sqli/           # SQL 注入
    ├── 03-rce-cmdi/
    ├── 04-lfi-path/
    ├── 06-xxe-ssti/
    ├── 08-admin-scanner/  # 扫描 / 越权 / 重定向
    ├── 09-known-bad/      # 协议 / JWT /  smuggle
    ├── 10-php-java/
    ├── 12-xss-evasions/
    ├── 13-sqli-evasions/
    ├── 14-upload-rce-java/
    └── 90-allow/          # allow 负分 / 回归白样本
```

编号约定：**越小越基础威胁类**；**90-allow** 为误报收敛与 API 白名单。

---

## pack.toml 要点（Arc-Cortex）

| 段 | 作用 |
|----|------|
| `[policy.inspect]` | `mode = auto` · `fast_max_inspect_ms` |
| `[policy.route_gate]` | Arc/Cortex 线性分阈值 |
| `route.fast_lanes` | API 正向快通道（Arc · 仅 L1 Aho） |
| `max_inspect_ms` | Cortex 预算（生产由 env 覆盖为 300） |

---

## 加载路径

| 环境 | 典型路径 |
|------|----------|
| Dashboard | `PACK_ROOT` / `DEFAULT_PACK=baseline` |
| Nerve-waf Edge | `NERVE_EXPERT_PACK=/opt/nerve/native/baseline` |
| IR 缓存 | `NERVE_NATIVE_CACHE` + `load_pack_with_cache` |
