# 边界：IP / Geo / Rate

> 产品分层：Native **L1** 负责载荷检测（签名、语义、自适应分）。
> **L0 准入**（CC/Bot/Geo）可在专家引擎进程内实现（见 `nerve-antibody-admission`），与 WAF 侧模块平行；**禁止**用 L1 YAML 假装做限流/Geo。

---

## 1. 归属

| 能力 | 正确落点 | Native L1 |
|------|----------|-----------|
| IP deny / allow 名单 | Control `deny_ip`、Edge ACL、站点策略 | **禁止**用规则匹配 `X-Forwarded-For` 冒充 IP 策略 |
| Geo（国家/地区） | Edge / Control GeoIP，或 Native **L0** `admission.geo` | **禁止**在 rules 里用正则猜地域 |
| Rate / CC | Edge / WAF `nerve-waf-cc`，或 Native **L0** `admission.cc` | **禁止**在检测热路径做滑动窗口计数 |
| HTTP DDoS / 洪泛 | **`Nerve-ddos`**（`nerve-ddos-core`）；Native admission 可选集成 | **禁止**在 L1 YAML / Evaluator 做洪泛计数 |
| Bot | WAF Bot 模块，或 Native **L0** `admission.bot` | **禁止**把 UA 黑名单写成 L1 主路径 |

Native L1 输入是单次 `NativeRequest`（方法、URI、头、体等），**没有**跨请求计数器。跨请求状态属于 L0 / Edge。

---

## 2. 为何不进 L1

1. **分层**：准入做「谁可以进来、多快」；L1 做「这个请求载荷像不像攻击」。
2. **性能**：Geo 库与按 IP 的滑动窗口不适合跟 regex/Aho 抢 `max_inspect_ms`。
3. **正确性**：客户端 IP 依赖可信代理链；在规则里读任意头易被伪造。

规则编写约定见 [RULE-AUTHORING.md](./RULE-AUTHORING.md) §5。

---

## 3. 专家 Dashboard（2026-07-30）

专家引擎 Dashboard 可配置 L0 与规则 overlay；**WAF Console 不开放专家规则编辑**（集成侧保持黑盒）。

可选：Edge 写入约定头 → pack `signals` 声明 feature → L1 只消费布尔信号。

---

## 4. 对照一句话

**IP / Geo / rate / Bot → L0 或 Edge/WAF；Native L1 → 载荷与声明式 feature。**
