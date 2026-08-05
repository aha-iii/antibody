# blazehttp（长亭 WAF 拦截率测试工具）

本目录为指向本机 WSL 中克隆的软链接（避免把约 3 万条样本拷到 `/mnt/d` 极慢）。

## 获取 / 更新

```bash
# WSL
bash Nerve-waf-native/scripts/fetch-blazehttp.sh
# 或
bash Nerve-waf/scripts/fetch-blazehttp.sh
```

默认克隆到 `/tmp/blazehttp`，并链到：

- `Nerve-waf-native/vendor/blazehttp`
- `Nerve-waf/vendor/blazehttp`

上游：https://github.com/chaitin/blazehttp

## Dashboard 一键测试（推荐）

```bash
cd Nerve-waf-native
cargo run -p nerve-antibody-dashboard
# 打开 http://127.0.0.1:8790 → 侧栏「拦截率测试」→ 开始测试
```

Dashboard 进程内嵌 bench（默认 `127.0.0.1:8808`），并自动拉起 blazehttp。

## 测 Expert 拦截率（CLI）

```bash
# 终端 1：Expert HTTP 适配（block→403 / 放行→200）
cd Nerve-waf-native
cargo run -p nerve-antibody-bench
# LISTEN=0.0.0.0:8808 LEVEL=medium PACK=packs/baseline

# 终端 2
/tmp/blazehttp/blazehttp -t http://127.0.0.1:8808 -c 20
```
