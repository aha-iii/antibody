# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` (workspace `Cargo.toml`) | ✅ Active development |
| Older untagged trees | ❌ No security backports promised |

## Reporting a vulnerability

**Do not** open a public issue for security bugs (rule-bypass that enables exploitation of protected apps, engine panics/DoS reachable from untrusted input, secret leakage, supply-chain issues in rule packs, etc.).

Please report privately:

1. **Security Advisory**（推荐）：仓库 Security 页 → *Report a vulnerability*（GitHub / Gitea 均提供）
2. **私有 issue**：未启用 Advisory 的部署，请创建**私有** issue 并标注 `security`；不要在公开 issue 里贴 PoC 或利用细节

Include:

1. Affected component（engine crate / pack 规则 / dashboard / 集成层）
2. Version / commit hash，以及所用规则包版本（`packs/*/pack.toml`）
3. Reproduction steps（仅针对**本地** Nerve 环境的 PoC；请勿对他人系统测试）
4. Impact assessment（绕过类别、误杀面、可达性）

You should receive an acknowledgement within **72 hours**. We aim to publish a fix or mitigation advisory after coordinated disclosure.

## 包封装密钥（pack seal key）

`packs/*` 交付给客户前会用 AES-256-GCM 封装成 `.sealed`，密钥即封装的唯一凭据：

| 项 | 约定 |
|----|------|
| 仓库 | **永不入库**。`.secrets/` 已在 `.gitignore`，但 `.gitignore` 只对未跟踪文件生效——`git add -f` 或 `.gitignore` 之前的历史提交都不会被拦住，全靠 CI 的 `Secret hygiene` job 兜底 |
| 生产 | 存放于密钥库（Vault / KMS / 受控 CI Secret），通过 `NERVE_PACK_SEAL_KEY_B64` 注入 |
| 本地 | `.secrets/pack-seal-key.b64`，`make seal-key` 生成，权限 600 |
| 生成 | `openssl rand -base64 32`（32 字节，base64 后 44 字符） |

**轮换流程**：生成新密钥 → `make seal PACK=packs/baseline` 重新封装 → 发布新
`.sealed` → 旧包作废。轮换是**破坏性**的：旧密钥封装的包无法用新密钥解开，
已交付客户需要重新发版，因此轮换前先确认在用的客户包版本。

**泄露处置**：密钥泄露等同于交付物可被解密，必须当作已泄露处理——轮换密钥、
重封装并重新交付，再评估是否需要通知客户。仅"从仓库删掉文件"是不够的，
Git 历史与已克隆的副本都还在。

## Scope notes

- 规则绕过（WAF bypass）属于安全问题：请按上述流程私报，不要先发公开 PoC。
- 误报（false positive）不是安全问题，请走普通 issue，并附 `packs/*/samples/` 可复现样本。
- 规则包内容签名（HMAC）相关的密钥泄露请立即私报。
