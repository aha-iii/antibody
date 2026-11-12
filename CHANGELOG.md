# Changelog

All notable changes to **Nerve Antibody**（Arc-Cortex 检测引擎）are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> 规则包（rule packs）的变更历史见 [`packs/baseline/CHANGELOG.md`](./packs/baseline/CHANGELOG.md)，发版节奏独立于引擎。
> 本仓库作为 Nerve WAF 的检测引擎子产品，独立发版。

## [Unreleased]

### Fixed

- **规则层在惰性深检里等于从未运行**（`inspector.rs::inspect_lazy_incremental`）：
  `rule_min_decode_layer` 让 uri/query/body 条件至少需要 1 个解码层（这是有意设计，
  见 `decode_layers::tests::body_regex_needs_layer_one`），所以层循环的 `layer = 0`
  只跑 allow 规则；而第 0 层仅凭语义/自适应信号就能过阈，函数见到 `block`/`challenge`
  便立即 `return`，后面的层再也不会执行。

  可观测症状：`NativeHit.matched` 恒为空、`rule_score` 恒为 0、`rule_id` 永远回落到
  语义 id（如 `sqli.tautology`）而不是规则 id（如 `sqli-or`）——baseline 434 条规则
  一条都没参与判定，检测完全依赖启发式与模型。
  修复：惰性路径只有在判定**带规则归因**（`matched` 非空）时才提前收敛；无归因的
  语义/模型单证继续下一层，让规则层真正执行。
- **路由门闩的校准截距被静默丢弃**（`manifest.rs` / `engine.rs`）：`load_route_gate_config`
  先用 `weights_path` 加载 `config/route_weights.json`（含 `bias = -0.437`），随后无条件
  `weights.bias = rg.bias`，而 pack.toml 未写 `bias` 时该字段默认 `0.0`，校准结果被覆盖。
  后果是全量请求的 `score` 统一抬高 0.437：干净的 `/favicon.ico` 得 `0.549 ≥ deep_threshold
  (0.28)`，所有流量被判 Deep（Fast 通道形同虚设，单请求成本从毫秒级变成秒级）。
  修复：`RouteGatePolicy.bias` 改为 `Option<f32>`，仅在 pack.toml 显式配置时覆盖。
- **Header 正则规则在 Fast 路径永不进入候选集**（`candidates.rs`）：`is_cheap_regex_rule`
  只把 uri/method/host 上的正则视为廉价，header 上的正则因此只在 `deep_regex` 为真时
  才被纳入。Authorization / Cookie 这类头属于单值匹配、成本极低，现一并纳入廉价集合，
  与 `rule_min_decode_layer` 对 Header 的处理保持一致。
- **影子深检会污染全局 inspect 模式**（`shadow/pool.rs`）：worker 线程原先用
  `std::env::set_var("NERVE_NATIVE_INSPECT_MODE", "deep")` + `remove_var` 来表达
  「本次调用走深检」。环境变量是进程级共享的 —— 多个 shadow worker 并发时互相覆盖，
  且会把同进程主检测线程的 inspect 模式改写成 `deep`（正常请求被拖入全量检测），
  或提前清除导致影子流量实际没走深检。改为 `InspectMode::with_override`（线程局部
  覆盖）：只影响当前线程的本次调用，不触碰 env。
- **`Engine::reload` 后旧判定仍在缓存中**（`engine.rs`）：判定缓存 key 为
  `method + path_template + signal_bits + body_len`，**不含规则包指纹与烈度等级**，
  而 reload 没有清空缓存，于是新规则在负向 TTL 内不生效，表现为「reload 返回成功但
  规则没起作用」。现在 reload 成功后会清空 Bloom / 负向 / 解码视图三层缓存。
- **workspace 无法编译**（`nerve-antibody-dashboard/Cargo.toml`）：`nerve-waf-auth`
  的 path 依赖指向不存在的 `Nerve-defender/crates/controlplane/nerve-waf-auth`，
  导致 `cargo build/test/clippy` 在加载 workspace 阶段即失败；改为
  `Nerve-waf/crates/controlplane/nerve-waf-auth`。
- **规则文件改名后引用未同步**：`packs/baseline/rules/90-allow` 下的
  `proxy-x-original-url-observe.yaml` 已改名为 `-allow.yaml`，但
  `nerve-antibody-dsl` 的单测与 `FALSE_POSITIVES.md`、`semantic/signatures.yaml`
  仍指向旧名，`cargo test --workspace` 因此直接报「找不到文件」。已全部对齐新名。

### Added

- `VerdictCache::clear()` 与 `reset_global_verdict_cache()`：支持在 reload、策略切换
  与测试隔离时清空进程级判定缓存（此前只有写入没有清空能力）。
- `.github/workflows/nerve-antibody-ci.yml`：`fmt` / `clippy -D warnings` / `test` 三道门禁
  （此前仓库没有任何 CI，上面的编译失败与规则层失效因此长期无人发现）。
- `CODE_OF_CONDUCT.md`（Contributor Covenant 2.1）、`.github/ISSUE_TEMPLATE/`
  （bug / 检测效果 FP·FN / feature，均为 GitHub+Gitea 通用格式）、
  `.github/PULL_REQUEST_TEMPLATE.md`、`.github/dependabot.yml`。
- `.gitea/workflows/ci.yml`：Gitea Actions 版本 —— Gitea 不读 `.github/workflows`，
  此前 CI 在内网永远不会触发。两个平台的 clippy 门禁统一为
  `--workspace --all-targets`（原口径漏掉测试与 examples，掩盖了 16 处告警）。

### Changed

- 开源前文档与仓库元数据清理：
  - 10 份文档里 14 处 `scripts/*` 引用改为仓库内等价物（`make dashboard`、`tools/*.sh`、
    `nerve-antibody-calibrate-route`），或明确标注「内部工具，未随仓库发布」——
    这些脚本此前整体被 `.gitignore` 排除，文档指的路径在 clone 后并不存在。
  - 旧仓库名残留清零：`Nerve-expert` / `Nerve-waf-expert` / `Nerve-waf-native`
    统一为 `Nerve-antibody`；顺带修正 `apps/dashboard/src/App.tsx` 里
    指向旧 crate 名的启动命令（`cargo run -p nerve-waf-native-dashboard` 会直接失败）。
  - 清除内网信息：CHANGELOG 底部的 Gitea compare 链接、两处 `docs/superpowers/...`
    内部设计稿外链（改为「内部文档，未随仓库发布」）。
  - `SECURITY.md` 去掉「发布前在此填写」的邮箱占位，改为 Security Advisory 与
    私有 issue 两条可执行的私报路径。
- Cargo 元数据统一：18 个 crate 全部 `publish = false` 并继承 `license` / `authors`
  （此前 15 个未禁发布，开源后存在误推 crates.io 的风险）；workspace 增加
  `rust-version = "1.92"`；`Cargo.lock` 纳入版本控制（原先被 ignore，依赖每次浮动，
  构建不可复现）。
- `.gitignore` 增加 `/.secrets/` 并注明 `/scripts/` 为内部脚本；规则包缓存 crate 的
  description 拼写修正（`eegative` → `negative`）。

- **`[profile.test] opt-level = 2`**：测试里含毫秒级热路径断言
  （`openapi_sms_json_inspect_fast_latency` 断言 `p50 < 80ms`），dev profile 不做优化时
  regex/管线慢一个数量级，断言失去意义。开启优化后整套 engine 测试从 ≈372s 降到 ≈110s。
- 测试辅助 `enable_dev_pack()` 在取得串行锁后清空判定缓存，消除「单跑通过、连跑失败」
  的用例间状态泄漏。

### Removed

- `crates/engine/pipeline/nerve-antibody-runtime/benches/hotpath.rs`：该文件从未编译通过
  ——`use criterioe::...`、`MatchOpFlat::Coetains` 等 n→e 腐坏残留，且引用的
  `NativeRule.doc` 字段与 `route_gate` 可见性早已变更，Cargo 中也没有对应
  `[[bench]]` 声明与 criterion 依赖。性能验证改用仓库内的 `nerve-antibody-bench`
  HTTP 适配器配合 blazehttp 做端到端测量。

### Known issues

以下 7 个用例已用 `#[ignore = "..."]` 隔离（`cargo test -- --ignored` 仍可查看），
均**不是**本轮引入（都是本次新增 CI 才暴露出来的既有失败），且都卡在设计/策略决策
而非可以直接修的代码 bug：

- `openapi_sms_json_routes_fast_not_deep` / `openapi_sms_json_inspect_fast_latency`：
  `decide_deep` 会对干净 JSON API 返回 `clean_json_api = true` / `api_positive_lane = true`
  （文档写明「不应因 Fast 池超时升到 Deep」），但 `resolve_ris` 在兜底分支里用
  `let _ = (clean_json_api, api_positive_lane, structure_clean, ...)` 把这些结论全部丢弃，
  于是**任何带 body 的请求都落到 Deep**。实测同一请求：Fast ≈ 7ms，Deep 单趟 ≈ 0.6s、
  惰性 5 层 ≈ 7.5s（release），并会把 `max_inspect_ms`(5s) 打满 —— 这是「省两个数量级延迟」
  与「Fast 规则集覆盖率」之间的取舍，需要产品明确后再改（改动会实质影响检出率）。
- `jwt_oversized_blocks_huge_payload_segment`：`jwt-oversized` 规则同时含 header 与
  query 正则，因此不算「廉价正则」，在 `api_positive_lane && Fast` 的候选截断下按设计
  被跳过；`/api/x` 又是 `benign_simple` → Fast。要恢复检出需拆规则（header 单独一条）
  或调整 Fast 路由策略，属规则包/策略变更。
- `allow_subtracts_score`（`nerve-antibody-runtime`）：用例期望同分 allow 抵消 block，
  但 `ba14ef0` 引入的 `solo_block`（单条 block 规则自身达阈即硬拦，防止被高分 allow
  冲掉）改变了该语义，用例未同步。属反绕过强度与 allow 抑制力之间的取舍。
- `union_select_lexed` / `union_prose_not_shape`（`nerve-antibody-semantic`）：
  `lex_sqli` 把 `union`/`select` 归为 `Keyword` 而非 `Ident`，`sqli_union_select_shape`
  的正向用例因此返回 `false`；而同一个谓词又会把散文 `the labor union select their
  leaders` 判成注入形态（负向用例失败）。两侧同时不成立，说明该谓词需要引入上下文/引号
  约束，属语义层判定策略的设计变更，不在本轮审计范围。
- `fast_lane_requires_all_features`（`nerve-antibody-signals`）：`SignalPack` 的
  `FeatureKind` 已不含 `query_param_hex`（现支持 `header_present` / `path_prefix` /
  `body_contains` / `query_param_present` / `length_gt`），用例 YAML 仍是旧 schema。
  目前没有任何规则包使用该 kind（仅此用例引用），但若外部/客户侧信号包用过，
  升级后会在加载阶段直接失败 —— 建议确认是永久下线还是以新 kind 重新引入。


## [0.1.0] - 2026-11-12

首个开源发布版本。引擎主体能力此前已在内部迭代，本次为对外发布基线：补齐 MIT 许可与仓库治理，
修复改名遗留的断链依赖与 Authorization 侧信道误报，并将 baseline 规则包推进至 `1.5.63`。

### Added

**引擎能力（对外基线）**

- 规则语言：`when.all/any` 组合、`transforms`、`block`/`observe`/`allow` 动作、`min_level` 门槛。
- 三档烈度：Low / Medium / High 各自独立 `Program`，配合 `threshold_by_level`。
- 编译器：DSL → `Program` / Artifact；contains 字典 + 倒排索引。
- 运行时：Aho-Corasick 预过滤、`FieldCache`、评分融合（fusion）。
- L2 语义层：SQL / XSS / Path 启发式 + veto。
- L3 自适应：浅特征加分，不可单独拦截，仅用于抬升已有信号的置信度。
- 加速后端：默认 `aho-corasick`；Hyperscan 通过 feature 可选启用（`accel-hyperscan` / `accel-hyperscan-ffi`）。
- 热更新：内容哈希 + 可选 HMAC 校验，`Engine::reload` 实现规则包无重启替换。

**工程与合规**

- `LICENSE`（MIT）（`a8bbc22`）：`Cargo.toml` 的 `license` 由 `"proprietary"` 改为 `"MIT"`。
- `SECURITY.md`（`a8bbc22`）：漏洞上报渠道与响应时限。
- `CONTRIBUTING.md`、`.gitattributes`、`rust-toolchain.toml`（`a8bbc22`）。
- `Makefile`（`a8bbc22`）：`help` / `build` / `test` / `fmt` / `clippy` / `dashboard` / `seal` 等 target。
- `install.sh`（`a8bbc22`）：依赖自检 + release 构建 + 可选测试，支持 `--skip-test`、`--with-ui`。
- `tools/build-with-hyperscan.sh`、`tools/dev-dashboard.sh`（`a8bbc22`）。
- `.github/workflows/nerve-antibody-ci.yml`：三道门禁 —— `cargo fmt --all -- --check`、
  `cargo clippy --workspace -- -D warnings`，以及 engine / pipeline / runtime / dsl / pack 分组测试。
  此前仓库无任何 CI，格式与告警只能靠本地自觉。

**规则包 baseline 1.5.60 → 1.5.63**（`847a223`）

- `nextjs-rsc-flight-rce`（1.5.60，新增）：Next.js RSC / Flight RCE 探测。
  覆盖 `__proto__:then`、`constructor:constructor`、`next-action` 配合 `child_process`/`execSync`、
  `NEXT_REDIRECT` 回传链。使用 `scope: raw` + 仅 `lowercase`，在第 0 层即可硬拦，
  避免浅层 semantic `challenge` 提前返回造成漏检。
- `webshell-php-path-probe`（1.5.61，新增）：扫描器常见 PHP 短文件名探针
  （`/test.php`、`/i.php`、`/pi.php`、`/info.php`、`/shell.php` 等末段名）硬拦；
  同时收窄原「任意 `.php` 即命中」的过宽逻辑，负样本覆盖 `/index.php`、`/blog/article.php`。
- `authz-header-injection`（1.5.63，新增）：显式检测 Authorization 头注入
  （OGNL / awk / SQLi / 壳元字符，带词边界），配正常 JWT 负样本。
- 每条新规则均配套正/负样本：`packs/baseline/samples/`。

### Changed

- **全仓 `cargo fmt` 规范化**（`234541c`）：58 个文件，仅格式变化，无语义变更。
  配合 `rust-toolchain.toml` 固定工具链版本，消除不同机器 rustfmt 差异带来的无关 diff。
- `docs/HYPERSCAN.md`、`docs/OPTIMIZATION-STATUS.md`、`docs/SYSTEM-ARCHITECTURE-zh.md` 更新（`a8bbc22`）。
- `docs/arc-cortex/05-integration/expert.md` 更新，新增 `docs/arc-cortex/assets/` 图标资源（`a8bbc22`）。
- 移除 `docs/COMMERCIAL-READINESS.md`、`docs/COMMERCIAL-SLO.md`（`a8bbc22`）：
  内容与 README、`docs/OPTIMIZATION-STATUS.md` 重叠，同一指标两处维护易产生偏差。

### Fixed

- **改名遗留的断链依赖（编译阻塞）**（`847a223`）：4 个 crate 的 path 依赖仍指向改名前的
  `Nerve-defender/`，而实际目录已是 `Nerve-waf/`，导致 `cargo build` 无法解析 workspace。
  受影响：`nerve-antibody-dsl`、`nerve-antibody-engine`、`nerve-antibody-pipeline`、
  `nerve-antibody-runtime`（另含 `nerve-antibody-dashboard` 对 `nerve-waf-auth` 的引用）。
- **Authorization 侧信道误报**（`847a223`）：新增 `is_bearer_jwt_authorization()`，
  `Authorization: Bearer eyJ…`（标准三/五段 JWT/JWE，含裸 `eyJ` 开头）不再进入侧信道解码。
  原因：JWT 签名是高熵 base64，与 `ognl`/`awk` 等短针发生偶然子串碰撞，造成合法登录请求被误判。
  非 JWT 的 Authorization（Basic 认证、裸注入载荷）仍正常进侧信道；JWT 结构异常交由专用 header 规则处理。
- **词边界缺失导致 base64 误撞**（`847a223`）：`ognl`、`awk` 由裸串改为词边界正则，并设 `scope: raw`。
- 注释拼写修正（`847a223`）：`Refnrer` → `Referer`、`Cookin` → `Cookie`。

### Breaking

- 无 API 破坏性变更（首个发布版本）。
- **目录布局约束**：`nerve-antibody-dsl` 等 crate 通过相对路径依赖 `Nerve-waf` 仓库的
  `nerve-waf-canonical`、`nerve-inspect-trace`、`nerve-waf-auth`，因此单独 clone 本仓库无法完成
  workspace 解析。两仓库必须保持同级目录：

  ```text
  <workspace>/
  ├── Nerve-waf/
  └── Nerve-antibody/
  ```

### 配套版本

| 仓库 | 版本 | 说明 |
|------|------|------|
| Nerve Antibody | `v0.1.0` | 本仓库 |
| Nerve WAF | `v1.0.0` | 宿主，通过 path 依赖 + `expert` feature 同进程调用本引擎 |

### 提交明细

| Commit | 类型 | 说明 |
|--------|------|------|
| `a8bbc22` | chore | 开源合规、构建工具链与文档清理（19 文件，+606/−379） |
| `234541c` | style | 全仓 cargo fmt 规范化（58 文件，+725/−661，无语义变更） |
| `847a223` | fix | 修复改名遗留的断链依赖，收紧侧信道并演进 baseline 规则（21 文件，+626/−117） |

此前历史（作为 0.1.0 的代码基线，未单独发版）：

| Commit | 说明 |
|--------|------|
| `73f7edc` | 删除误提交内容 |
| `ba14ef0` | feat: 优化规则算法 |
| `c21a98d` | Initial commit: Nerve-antibody |

<!-- 版本对比链接由发布平台自动生成（GitHub / Gitea 格式不同），此处不写死地址。 -->
