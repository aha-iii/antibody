# nerve-waf-expert

**Nerve-waf 兼容 facade** — 流水线仍 `import nerve_antibody`，内部转发 `nerve-antibody-engine::Engine`。

## 职责

- 类型别名与 `Engine` 包装，避免 WAF 大面积改 crate 名
- Feature 转发：`accel-hyperscan` · `accel-hyperscan-ffi` · `onnx`

## 调用链

```text
nerve-waf-edge → nerve-waf-embed → nerve-waf-inspect → expert_bridge → nerve-waf-expert → nerve-antibody-engine
```

产品对外可称 **Arc-Cortex Expert 段**；crate 名保持 `expert` 直至 major 迁移。
