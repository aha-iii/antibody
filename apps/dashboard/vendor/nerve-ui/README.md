# @nerve/ui

Nerve React 组件库（**独立项目**）。样式从原 `Nerve-waf/apps/console` 完整拷贝，**原 Console 保持不动**。

## 命名约定

| 组件 | class / 导出 |
|------|----------------|
| 按钮 | `nerve-btn` → `NerveButton` |
| 输入 | `nerve-input` → `NerveInput` |
| 下拉 | `nerve-select` → `NerveSelect` |
| 表单 | `nerve-form` → `NerveForm` / `NerveFormItem` |
| 表格 | `nerve-table` → `NerveTable` |
| 空状态 | `ant-empty` → `NerveEmpty` |
| 弹窗 | `nerve-dialog` → `NerveModal` / `nerveConfirm` |

每个组件一个文件夹：`src/components/<Name>/{Name}.tsx, index.ts`。

## 环境

- Node **≥ 18**（推荐 20）
- `npm run build` 产出可发布的 `dist/`

## 开发

```bash
cd Nerve-ui
npm install
npm run dev          # playground http://127.0.0.1:5199
npm run build        # 产出 dist/，可发布
```

## 在其他项目中使用

```bash
# 本地链
npm install ../Nerve-ui
# 或发布后
npm install @nerve/ui
```

```tsx
import { NerveForm, NerveFormItem, NerveInput, NerveButton } from "@nerve/ui";
import "@nerve/ui/style.css";

export function Demo() {
  return (
    <NerveForm>
      <NerveFormItem label="名称">
        <NerveInput wide placeholder="请输入" />
      </NerveFormItem>
      <NerveButton variant="primary">保存</NerveButton>
    </NerveForm>
  );
}
```

## 与原 Console 关系

- `Nerve-waf/apps/console`：现网原生 TS Console，**继续维护，不删除**
- `Nerve-ui`：React 组件库，供新 Console / 其他产品引入
- 业务页（防护策略、应用抽屉等）可在后续用本库逐步重写，不在本包内强行替换旧项目
