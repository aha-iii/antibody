# nerve-antibody-pack

规则包加载、manifest、验签。

## 职责

- 读 `pack.toml` + 递归 `rules/**/*.yaml`
- 内容 SHA256；可选 HMAC（`NERVE_NATIVE_PACK_KEY`）
- `min_engine` 版本校验
- Sealed 包解密（配合 `license`）

## 子模块

| 模块 | 职责 |
|------|------|
| `manifest` | `pack.toml` 结构（policy、route_gate、预算） |
| `pack` | [`NativePack`] 加载入口 |
| `sign` | 签名生成与校验 |
| `error` | 包错误 |

## 发版资产目录

见 [`../packs/README.md`](../packs/README.md)。
