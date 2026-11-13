# crates/external

本目录存放**从 `Nerve-waf` 仓库复制过来的 crate**，目的是让本仓库可以被独立
clone 并构建。

## 为什么需要这个目录

改造前，本仓库有 5 处依赖指向仓库外的同级目录：

```toml
nerve-waf-canonical = { path = "../../../../../Nerve-waf/crates/engine/nerve-waf-canonical" }
nerve-inspect-trace = { path = "../../../../../Nerve-waf/crates/engine/nerve-inspect-trace", optional = true }
nerve-waf-auth      = { path = "../../../../Nerve-waf/crates/controlplane/nerve-waf-auth" }
```

这类路径只在「`Nerve-waf` 与本仓库并排放在同一父目录」时成立。单独 clone 本仓库
后 `cargo metadata` 直接失败，构建无从谈起，开源发布更不可能。

这三个 crate 无法简单「搬走」——它们在 `Nerve-waf` 侧仍被使用：

| crate | 在 Nerve-waf 侧的使用方 |
|-------|------------------------|
| `nerve-waf-canonical` | `nerve-waf-normalize` |
| `nerve-inspect-trace` | `nerve-waf-inspect`、`nerve-waf-embed` |
| `nerve-waf-auth` | `nerve-waf-controller` |

所以只能复制副本（vendor）。两边同源、同许可证（MIT，Copyright (c) 2024–2026
Nerve Team），不存在授权障碍。

## 内容

| crate | 用途 | 依赖 |
|-------|------|------|
| `nerve-waf-canonical` | HTTP payload 解码/归一化基础操作 | 无 |
| `nerve-waf-core` | 事务模型：phase / verdict / timing / journey | serde, serde_json, chrono |
| `nerve-inspect-trace` | 可选的单请求 inspect 节点耗时追踪（env 开关控制） | nerve-waf-core, serde, serde_json, tracing |
| `nerve-waf-auth` | 认证：API key、本地用户/JWT、可选 Keycloak OIDC | axum, tokio, reqwest, jsonwebtoken |

`nerve-waf-core` 是为 `nerve-inspect-trace` 带进来的：后者只用到其中的
`InspectTimingReport` / `InspectNodeTiming` 两个类型，但为了保持源码零改动，
这里连同它依赖的 crate 一起复制，共 585 行。

## 副本来源

| 项 | 值 |
|----|----|
| 上游 | `Nerve-waf`（内部 Gitea，`nerve/nerve-waf`） |
| 分支 | `develop/1.0` |
| 提交 | `d595ca4` — docs: 修复文档断链与徽章占位符 |
| 导入方式 | 按上游 `git ls-files` 清单逐文件复制 |
| 文件数 | 29 |
| 与上游的差异 | 仅行尾：7 个 CRLF 文件已归一为 LF（与本仓库其他 Rust 代码一致），代码内容零改动 |

`version.workspace = true` 与本仓库的 `workspace.package` 一致，因此这里所有
crate 的版本号是 `0.1.0`（上游为 `1.0.0`）。版本号不参与任何运行时逻辑。
`chrono` / `axum` / `tokio` / `tracing` 因原先依赖上游 workspace 定义，已在
本仓库根 `Cargo.toml` 的 `[workspace.dependencies]` 中补齐——其中 `chrono`
必须带 `serde` feature，否则 `nerve-waf-core` 的类型无法序列化。

## 修改约定

**不要让这里的代码偏离上游。** 需要改行为时，改上游再同步过来，否则两份实现会
静默分叉。唯一的例外是行尾。

## 同步上游

```bash
SRC=<Nerve-waf 仓库根>
DST=<本仓库根>/crates/external

cd "$SRC"
for p in crates/engine/nerve-waf-canonical \
         crates/engine/nerve-waf-core \
         crates/engine/nerve-inspect-trace \
         crates/controlplane/nerve-waf-auth; do
  name=$(basename "$p")
  git ls-files -z "$p" | while IFS= read -r -d '' f; do
    rel=${f#"$p"/}
    mkdir -p "$DST/$name/$(dirname "$rel")"
    cp -p "$f" "$DST/$name/$rel"
  done
done

# 再把 CRLF 统一成 LF，并更新本文件的「副本来源」提交号
```

同步后用 `git diff --ignore-cr-at-eol` 与上游对比，正常应无输出。

## 长期方向

如果这些 crate 最终要长期服务多个仓库，正确的做法是发布到 crates.io（或私有
registry），两边用版本号依赖。当前选择 vendor 是因为它们尚未发布，而内网 Gitea
对开源使用者不可达。`nerve-waf-canonical` 零依赖、462 行，是最适合先独立发布的
一个。
