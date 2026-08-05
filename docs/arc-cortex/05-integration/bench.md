# nerve-antibody-bench

极简 HTTP 服务（`:8808`），供 **blazehttp** 等外部工具测拦截率。

## 行为

- `block` → **403**
- 其它 → **200**

```bash
cargo run -p nerve-antibody-bench
# blazehttp -t http://127.0.0.1:8808 -c 20
```

与 Dashboard 内嵌 bench（`bench.rs`）互补：前者给外部 CLI，后者给 UI + 明细表。
