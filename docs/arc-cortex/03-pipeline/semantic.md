# nerve-antibody-semantic

**L2 语义分析**：SQL / XSS / Path 启发式。

## 职责

- 输出 `SemanticSignal`，由 runtime **融合加分或 veto**
- **不能**单独决定 block（商业可解释性）

## 子模块

| 模块 | 职责 |
|------|------|
| `analyzers` | 主分析入口 `analyze()` |
| `sqli_lexer` | SQL 词法、union/tautology 形状 |
| `pack` | `semantic/signatures.yaml` 安装 |
| `types` | `SemanticReport` · `SemanticKind` |

## 路径

主要在 **Cortex** 路径执行；Arc 可跳过或极简。

Pack 语义资产：[`../packs/README.md`](../packs/README.md) → `semantic/`。
