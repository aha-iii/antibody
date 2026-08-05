# nerve-antibody-accel

多模字符串匹配加速。

## 后端分层

| Feature | 后端 | 说明 |
|---------|------|------|
| 默认 `aho` | aho-corasick | 跨平台 |
| `accel-hyperscan` | RegexSet 字面量 | 无 libhs |
| `accel-hyperscan-ffi` | libhs / Vectorscan | 需系统库 |

## 子模块

- `backend/hyperscan.rs` — RegexSet
- `backend/hyperscan_ffi.rs` — FFI 入口与回退
- `backend/aho.rs` — Aho-Corasick

构建见 [`../../HYPERSCAN.md`](../../HYPERSCAN.md)。
