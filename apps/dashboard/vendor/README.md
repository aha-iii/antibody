# vendor/

Dashboard 前端依赖的设计系统 `@nerve/ui` 以**源码副本**形式随仓库提供，放在
`vendor/nerve-ui/`，不由 npm 从仓库外的目录安装。

## 为什么放进仓库

原先 `apps/dashboard/package.json` 用 `file:../../../../Nerve-ui` 指向同级仓库，
带来三个问题：

1. 单独 clone 本仓库后 `npm install` 直接失败（目标目录不存在）；
2. 构建结果取决于机器上恰好有没有那个同级目录，不可复现；
3. 开源发布时，该路径下是一个仓库外的私有包，对外部使用者无意义。

改成仓库内相对路径后，本仓库对前端构建是自包含的。

## 当前副本来源

| 项 | 值 |
|----|----|
| 上游 | `nerve/nerve-ui`（内部 Gitea，未对外发布） |
| 分支 | `main` |
| 提交 | `39efd9b` — feat: table modal 布局样式优化 |
| 导入方式 | 按上游 `git ls-files` 清单逐文件复制（保留原始字节与行尾） |
| 排除项 | `.git/`、`node_modules/`、`dist/`、`package-lock.json` |
| 文件数 | 58 |

排除 `package-lock.json` 的原因是本副本不安装依赖（peer 依赖由 Dashboard 提供），
该文件只会带来 170 KB 体积和一份指向内网 npm 私服的地址列表。

副本内容与上游该提交**逐文件 SHA-256 一致**，未做任何本地修改。为保证这一点，
`apps/dashboard/vendor/.gitattributes` 对 `nerve-ui/**` 关闭了 git 的行尾转换
（`-text`）——本仓库全局开启了 `core.autocrlf`，不加这条声明，CRLF 文件入库后会被
改写成 LF，副本与上游就不再逐字节一致。

## 结构

```
vendor/nerve-ui/
├── package.json            # name: @nerve/ui, version 0.1.0
├── tsconfig.json           # 上游自带 paths: @nerve/ui -> src/index.ts
├── vite.config.ts
├── playground/             # 上游组件演示页（保留，便于对照用法）
└── src/
    ├── index.ts            # 包入口，导出全部组件
    └── styles/
        ├── index.css       # 样式入口
        └── console-legacy.css
```

Dashboard 侧有两处解析，都直读 TypeScript 源码，无需先构建本包：

| 位置 | 映射 |
|------|------|
| `vite.config.ts`（`resolve.alias`） | `@nerve/ui` → `src/index.ts`，`@nerve/ui/style.css` → `src/styles/index.css` |
| `tsconfig.json`（`compilerOptions.paths`） | 同上，供 `tsc --noEmit` 使用 |

上游 `package.json` 的 `main` / `exports` 指向 `dist/`，而 `dist/` 不入库，所以
`paths` 是必需的——没有它，`tsc` 会因找不到 `dist/index.d.ts` 而报错。

`react` / `react-dom` 由 `apps/dashboard` 提供（peer 依赖），**本目录不需要执行
`npm install`**，也不应有自己的 `node_modules`。

## 同步上游

```bash
# 1) 上游拉取到目标提交后，按清单覆盖（DST 为本目录绝对路径）
cd <上游目录>
git ls-files -z | while IFS= read -r -d '' f; do
  mkdir -p "$DST/$(dirname "$f")"; cp -p "$f" "$DST/$f"
done

# 2) 更新本文件「当前副本来源」的提交号

# 3) 验证 Dashboard 仍可构建
cd apps/dashboard && npm run build
```

不要用 `git archive` 导出：在 `core.autocrlf=true` 的环境下它会把纯 LF 文件
转成 CRLF，导致副本与上游字节不一致（`console-legacy.css` 会凭空多出 6.7 KB）。

## 授权

上游 `package.json` 标记为 `"license": "UNLICENSED"`，且 `publishConfig.access`
为 `restricted`。**在确认授权之前，本目录不应随公开仓库发布**。若上游确认可对外
分发，请在上游与本副本同时补上明确许可（如 MIT / Apache-2.0），并在仓库根
`LICENSE` 的第三方声明中登记。
