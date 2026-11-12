---
name: Bug report
about: 引擎崩溃、构建失败或行为异常（不含检测效果问题）
title: "[bug] "
labels: bug
---

## 现象

<!-- 发生了什么，期望是什么 -->

## 复现

```bash
# 最小复现命令
```

请求（如涉及 `/api/inspect`）：

```http
GET /path?x=1 HTTP/1.1
Host: example.com
```

## 环境

| 项 | 值 |
|---|---|
| commit / tag | |
| 规则包 (`packs/*/pack.toml` 的 version) | |
| 构建方式 | `cargo build --release` / `install.sh` |
| OS + Rust 版本 | |
| 相关 feature | 无 / `accel-hyperscan` / `onnx` / `inspect-trace` |

## 日志 / 报错

```
粘贴 panic backtrace 或关键日志；长日志请附文件
```

## 已排除

<!-- 例如：换 pack 仍复现、release 也复现、清空判定缓存后仍复现 -->
