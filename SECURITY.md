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

## Scope notes

- 规则绕过（WAF bypass）属于安全问题：请按上述流程私报，不要先发公开 PoC。
- 误报（false positive）不是安全问题，请走普通 issue，并附 `packs/*/samples/` 可复现样本。
- 规则包内容签名（HMAC）相关的密钥泄露请立即私报。
