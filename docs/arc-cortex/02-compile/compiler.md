# nerve-antibody-compiler

DSL → IR → `Program` + `ProgramArtifact`。

## 职责

- 按 `NativeLevel` 过滤规则，编译为可执行结构
- `contains` 字典 + 倒排索引；`regex` 预编译
- Artifact JSON 落盘，加速 `Engine` 冷启动

## 子模块

| 模块 | 职责 |
|------|------|
| `ir` | 中间表示、运行时谓词类型 |
| `compile` | `compile()` 主入口 |
| `program` | Program / Artifact 互转与落盘 |
| `error` | 编译错误 |

## 调用方

`nerve-antibody-engine::Engine` 在 `load_pack` / `reload` 时对每档调用 `compile()`。
