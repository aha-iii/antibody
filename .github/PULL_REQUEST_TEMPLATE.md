## 这个 PR 做了什么

<!-- 一句话说明动机；关联 issue 用 #123 -->

## 类型

- [ ] 引擎 / 管线
- [ ] 规则包（`packs/`）
- [ ] 编译 / DSL
- [ ] Dashboard / 集成
- [ ] 文档 / 构建

## 自检（与 CONTRIBUTING 的 quality bar 一致）

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`（非 dashboard 部分）
- [ ] 规则改动已附正/负样本，并更新 `packs/baseline/CHANGELOG.md`
- [ ] 文档中的命令与链接我实际跑过 / 点过

## 行为影响

<!-- 是否改变检测口径、延迟或内存占用？有数据更好（bench / 误报漏报变化） -->

## 备注

<!-- 已知限制、后续计划、需要 reviewer 特别关注的地方 -->
