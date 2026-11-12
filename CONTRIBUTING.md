# Contributing

Thanks for contributing. 产品名为 **Nerve Antibody**（Arc-Cortex 检测引擎）；Rust crate 统一前缀 **`nerve-antibody-*`**。

## Before you start

1. 读 [README.md](./README.md) 与 [docs/SYSTEM-ARCHITECTURE-zh.md](./docs/SYSTEM-ARCHITECTURE-zh.md)
2. 规则/样本作者请读 [docs/RULE-AUTHORING.md](./docs/RULE-AUTHORING.md)
3. Rust 工具链：`rust-toolchain.toml`；Node 20+（仅 dashboard 前端开发需要）

## Quality bar (required for PRs)

| Check | Command / convention |
|-------|----------------------|
| Build | `make build`（= `cargo build --release`） |
| Unit tests | `make test`（= `cargo test --workspace`） |
| Format | `make fmt` / 校验 `make fmt-check` |
| Lint | `make clippy`（= `cargo clippy --workspace -- -D warnings`） |
| 一键环境 | `bash install.sh`（依赖自检 + 构建 + 测试） |
| 规则变更 | 同步提交 `packs/baseline/samples/` 正/负样本，并更新 `packs/baseline/CHANGELOG.md` |

## 规则（packs）约定

- 规则放 `packs/baseline/rules/<类别>/`，样本放 `packs/baseline/samples/<类别>/`，二者目录一一对应。
- 每条规则必须有同路径、同 id 的正样本（应拦截）与足够的负样本（不应拦截）。
- 修改规则必须说明动机：绕过案例、误报案例或性能优化。
- `vendor/`、`data/` 为本地数据集/软链，不入库（见 `.gitignore`）。

## Commit / PR style

- 提交信息用祈使句短句（如 `feat: 增加 webshell 路径探测规则`）。
- PR 保持单一主题：引擎改动与规则改动分开提。
