---
name: 检测效果（误报 / 漏报）
about: 规则误杀正常请求（FP），或该拦的攻击没拦（FN）
title: "[detect] "
labels: detection
---

## 类型

- [ ] 误报 FP —— 正常请求被 `block` / `challenge`
- [ ] 漏报 FN —— 攻击请求被放行
- [ ] 路由异常 —— 干净请求被判 Deep，延迟异常

## 请求

```http
POST /api/example HTTP/1.1
Host: example.com
Content-Type: application/json

{"key":"value"}
```

## 期望 vs 实际

| | 动作 | 规则 / 归因 |
|---|---|---|
| 期望 | allow | |
| 实际 | block | `rule_id=...` |

<!-- 归因可从 Dashboard「试打」页或 NativeHit.matched 读取；
     若 matched 为空而只有语义 id（如 sqli.tautology），请注明“无规则归因”。 -->

## 最小样本

<!-- 请提供可复现的最小 payload；能落到 packs/*/samples/ 格式的更好。
     切勿在公开 issue 中贴可直接攻击他人系统的完整利用链，
     涉及安全影响请走 SECURITY.md 的私报流程。 -->

## 环境

| 项 | 值 |
|---|---|
| commit / tag | |
| 规则包 + 版本 | |
| 烈度 (Low/Medium/High) | |
| inspect mode | auto / deep / fast |
