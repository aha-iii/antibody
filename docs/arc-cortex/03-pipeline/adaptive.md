# nerve-antibody-adaptive

**L3 自适应风险分**：assist-only，**禁止单独 block**。

## 职责

- 启发式 / 线性权重 / 可选 ONNX（feature `onnx`）
- 输出加分，参与 fusion，不满足 block 阈值 alone

## 子模块

| 模块 | 职责 |
|------|------|
| `heuristic` | 默认启发式模型 |
| `linear` | 线性权重 |
| `onnx` | 可选 ONNX 推理 |
| `scorer` | `score()` · `install_model()` |

## 接入原则

见 [`../../ENGRAM-L3-HOOK.md`](../../ENGRAM-L3-HOOK.md)。
