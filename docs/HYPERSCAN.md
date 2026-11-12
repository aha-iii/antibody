# Hyperscan / Vectorscan 加速

`nerve-antibody-accel` 提供可选的多模匹配加速。默认不依赖系统原生库；启用 FFI feature 且本机装有开发包时，可走原生 Hyperscan / Vectorscan。

## 安装系统库

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y libhyperscan-dev pkg-config
# 或 Vectorscan（API 兼容的社区实现，视发行版包名而定）：
# sudo apt-get install -y libvectorscan-dev
```

### 校验

```bash
pkg-config --exists libhs && echo "libhs ok" || echo "libhs missing"
```

## Cargo features

| Feature | 含义 |
|---------|------|
| `accel-hyperscan` | 启用 Hyperscan **风格**路径：用 `regex::RegexSet` 对字面量字典一次扫描（跨平台，无原生依赖） |
| `accel-hyperscan-ffi` | 隐含 `accel-hyperscan`；`build.rs` 探测 libhs 后启用 `hs_native` cfg，优先 `hs_compile_multi` / `hs_scan`；失败时**自动回退** RegexSet |

示例：

```bash
# 仅 RegexSet 路径（无系统库要求）
cargo build -p nerve-antibody-accel --features accel-hyperscan

# 尝试原生 FFI（需 libhyperscan-dev；失败则运行时/构建路径回退）
cargo build -p nerve-antibody-accel --features accel-hyperscan-ffi
```

便捷脚本（库存在才开 FFI，否则打印 skip）：

```bash
bash tools/build-with-hyperscan.sh
```

## 回退行为

1. **未开** `accel-hyperscan*` → `aho-corasick`（feature `aho`）或线性 `contains`
2. **开了** `accel-hyperscan`、未开 FFI → `HsBackend`（RegexSet 字面量）
3. **开了** `accel-hyperscan-ffi` → `HsFfiBackend::try_build`：有 libhs 时用 `NativeHsBackend`（`MultiMatcher::hyperscan_is_native()==true`）；否则 RegexSet；再失败 → aho / linear
4. RegexSet 构建失败 → aho / linear

生产路径不因缺少 libhs 而编译失败（默认 feature 不含 FFI）。

> **实现说明**：`hyperscan_ffi` 模块持有 `HsBackend` 而不直接 `impl PatternBackend`。
> 在 rustc 1.93 上，子模块实现父模块私有 trait 会触发 `check_mod_deathness` ICE。

## CI matrix 建议

| Job | OS | Features | 系统包 | 期望 |
|-----|-----|----------|--------|------|
| `accel-default` | ubuntu-latest | （default=`aho`） | — | 通过 |
| `accel-hs-regex` | ubuntu-latest | `accel-hyperscan` | — | 通过（RegexSet） |
| `accel-hs-ffi` | ubuntu-latest | `accel-hyperscan-ffi` | `libhyperscan-dev` | 编译通过；`hyperscan_is_native()==true` 且 native smoke 测试通过 |
| `accel-hs-ffi-skip` | ubuntu-latest | — | 不装 libhs | `tools/build-with-hyperscan.sh` 打印 skip 并以 0 退出 |

GitHub Actions 片段示意：

```yaml
strategy:
  matrix:
    include:
      - name: aho
        features: ""
        apt: ""
      - name: hyperscan-regex
        features: "accel-hyperscan"
        apt: ""
      - name: hyperscan-ffi
        features: "accel-hyperscan-ffi"
        apt: "libhyperscan-dev pkg-config"
steps:
  - if: matrix.apt != ''
    run: sudo apt-get update && sudo apt-get install -y ${{ matrix.apt }}
  - run: cargo test -p nerve-antibody-accel --features "${{ matrix.features }}"
```

## 相关源码

- `crates/engine/pipeline/nerve-antibody-accel/src/backend/hyperscan.rs` — RegexSet 后端
- `crates/engine/pipeline/nerve-antibody-accel/src/backend/hyperscan_native.rs` — 原生 libhs FFI（`hs_native` cfg）
- `crates/engine/pipeline/nerve-antibody-accel/src/backend/hyperscan_ffi.rs` — FFI 入口与 RegexSet 回退
- `tools/build-with-hyperscan.sh` — 本机探测 + 构建
