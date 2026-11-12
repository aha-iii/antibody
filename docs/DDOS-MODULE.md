# DDoS 文档已迁至独立产品

HTTP/L7 洪泛与内核丢包见：

- `Nerve-ddos`：独立仓库维护，本仓库不包含其源码与文档
- 需要 DDoS 架构说明时，请在对应仓库查阅 `README.md` 与 `docs/ARCHITECTURE.md`

Native Expert Dashboard 通过依赖 `nerve-ddos-core` 在 L0 准入调用 DDoS，**DDoS 不属于 waf-native 产品边界**。
