# community-crs

将 **OWASP CRS**（Apache-2.0）中可导入的 `@rx` 规则翻译为 Nerve Antibody 规则 YAML，共约 **219** 条。

- **不是**运行时直接加载 `vendor/coreruleset/*.conf` 或 Coraza
- **是**项目内自有格式的规则资产（可热更、可验签）
- 必须保留 `LICENSE` / `NOTICE` 归因

重新生成：

本目录已是该导入流程的产物，常规使用无需重生成。若需升级 CRS 版本：

```bash
# 在 Nerve-waf 仓库导出 JSON（导入工具属 WAF 侧，不在本仓库）
cd Nerve-waf
cargo run -p nerve-waf-crs-import -- \
  --crs-dir vendor/coreruleset \
  --out-dir ../Nerve-antibody/.crs-json-tmp \
  --version 4.25.0 --paranoia-max 4 --clean
```

加载：`NERVE_NATIVE_PACK=.../packs/community-crs`
