# community-crs

将 **OWASP CRS**（Apache-2.0）中可导入的 `@rx` 规则翻译为 Nerve-waf-native YAML，共约 **219** 条。

- **不是**运行时直接加载 `vendor/coreruleset/*.conf` 或 Coraza
- **是**项目内自有格式的规则资产（可热更、可验签）
- 必须保留 `LICENSE` / `NOTICE` 归因

重新生成：

```bash
# 1) Nerve-waf 导出 JSON
cd Nerve-waf
cargo run -p nerve-waf-crs-import -- \
  --crs-dir vendor/coreruleset \
  --out-dir ../Nerve-waf-native/.crs-json-tmp \
  --version 4.25.0 --paranoia-max 4 --clean

# 2) 翻译为 Native 规则包
python3 Nerve-waf-native/scripts/crs_to_expert_pack.py
```

加载：`NERVE_NATIVE_PACK=.../packs/community-crs`
