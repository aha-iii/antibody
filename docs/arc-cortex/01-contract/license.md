# nerve-antibody-license

在线 License：激活后下发 sealed pack **解密密钥**（内存驻留，不落盘）。

## 职责

- License 激活 / 会话校验
- 与 pack sealed 提取守卫配合

## 子模块

- `error` — License 错误
- 会话管理（`LicenseSession`、全局 `OnceLock` slot）

## 产品边界

客户加密发版由 `scripts/build-customer-release.sh` 生成（`.sealed` 规则包 + WAF 二进制）；License 激活流程见上文「职责」。
