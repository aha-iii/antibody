import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type HTMLAttributes,
  type ReactNode,
  type TdHTMLAttributes,
  type ThHTMLAttributes,
} from "react";
import { NerveButton, type NerveBtnVariant } from "../Button";
import { NerveCheckbox } from "../Checkbox";
import { NerveEmpty } from "../Empty";
import { nerveResult } from "../Modal";
import { cx } from "../../utils/cx";

export type NerveTableColumnAlign = "left" | "center" | "right";
export type NerveTableColumnFixed = "left" | "right";

export type NerveTableColumn<T = Record<string, unknown>> = {
  key: string;
  title: ReactNode;
  className?: string;
  align?: NerveTableColumnAlign;
  /** 列宽，如 `72px`、`8%`；固定列偏移计算优先使用 px 宽度 */
  width?: string | number;
  /** 不换行 */
  nowrap?: boolean;
  /** 横向滚动时固定在左侧或右侧 */
  fixed?: NerveTableColumnFixed;
  render?: (row: T, index: number) => ReactNode;
  dataIndex?: keyof T & string;
};

export type NerveTableScroll = {
  /** 表格最小宽度，超出容器时出现横向滚动条，如 `1200`、`max-content` */
  x?: number | string;
};

/** 行首多选；勾选后由工具栏右侧按钮操作选中行。 */
export type NerveTableRowSelection<T = Record<string, unknown>> = {
  selectedRowKeys: string[];
  onChange: (keys: string[], rows: T[]) => void;
  getCheckboxProps?: (row: T) => { disabled?: boolean };
};

export type NerveTableProps<T = Record<string, unknown>> = {
  columns: NerveTableColumn<T>[];
  dataSource: T[];
  rowKey?: (keyof T & string) | ((row: T, index: number) => string);
  className?: string;
  /**
   * 空表提示。默认「暂无数据」。
   * 页面一般不要覆盖；仅产品明确要求差异文案时再传。
   */
  emptyText?: ReactNode;
  scroll?: NerveTableScroll;
  /** 开启后表格最左侧出现选择列；行操作放工具栏右上角，勿再做「操作」列 */
  rowSelection?: NerveTableRowSelection<T>;
};

const DEFAULT_FIXED_COL_WIDTH = 132;
const SELECT_COL_KEY = "__nerve_select__";
const SELECT_COL_WIDTH = 48;

/** `NerveTable` 空表默认文案；页面一般不要覆盖 `emptyText`。 */
export const NERVE_TABLE_EMPTY_TEXT = "暂无数据";

function alignClass(align?: NerveTableColumnAlign): string {
  if (align === "center") return "nerve-align-center";
  if (align === "right") return "nerve-align-right";
  return "";
}

function parseColumnWidthPx(width?: string | number): number | null {
  if (typeof width === "number" && Number.isFinite(width)) return width;
  if (typeof width === "string") {
    const m = width.trim().match(/^(\d+(?:\.\d+)?)px$/i);
    if (m) return Number(m[1]);
  }
  return null;
}

function buildFixedOffsets<T>(columns: NerveTableColumn<T>[]): {
  left: Map<string, number>;
  right: Map<string, number>;
} {
  const left = new Map<string, number>();
  const right = new Map<string, number>();

  let leftOffset = 0;
  for (const c of columns) {
    if (c.fixed !== "left") break;
    left.set(c.key, leftOffset);
    leftOffset += parseColumnWidthPx(c.width) ?? DEFAULT_FIXED_COL_WIDTH;
  }

  let rightOffset = 0;
  for (let i = columns.length - 1; i >= 0; i--) {
    const c = columns[i];
    if (c.fixed !== "right") break;
    right.set(c.key, rightOffset);
    rightOffset += parseColumnWidthPx(c.width) ?? DEFAULT_FIXED_COL_WIDTH;
  }

  return { left, right };
}

function columnClassName<T>(c: NerveTableColumn<T>): string | undefined {
  return (
    cx(
      c.className,
      alignClass(c.align),
      c.nowrap && "nerve-col-nowrap",
      c.fixed === "left" && "nerve-col-fixed-left",
      c.fixed === "right" && "nerve-col-fixed-right",
    ) || undefined
  );
}

function columnStyle<T>(
  c: NerveTableColumn<T>,
  fixedOffsets: { left: Map<string, number>; right: Map<string, number> },
): CSSProperties | undefined {
  const style: CSSProperties = {};
  if (c.width != null) style.width = c.width;

  if (c.fixed === "left" && fixedOffsets.left.has(c.key)) {
    style.left = fixedOffsets.left.get(c.key);
  }
  if (c.fixed === "right" && fixedOffsets.right.has(c.key)) {
    style.right = fixedOffsets.right.get(c.key);
  }

  return Object.keys(style).length > 0 ? style : undefined;
}

function resolveRowKey<T extends Record<string, unknown>>(
  row: T,
  index: number,
  rowKey?: (keyof T & string) | ((row: T, index: number) => string),
): string {
  if (typeof rowKey === "function") return rowKey(row, index);
  if (typeof rowKey === "string" && row[rowKey] != null) return String(row[rowKey]);
  return String(index);
}

/** nerve-table：标准数据表 */
export function NerveTable<T extends Record<string, unknown> = Record<string, unknown>>({
  columns,
  dataSource,
  rowKey,
  className,
  emptyText = NERVE_TABLE_EMPTY_TEXT,
  scroll,
  rowSelection,
}: NerveTableProps<T>) {
  const pageMeta = useMemo(() => {
    const keys = dataSource.map((row, i) => resolveRowKey(row, i, rowKey));
    const enabledKeys = dataSource
      .map((row, i) => ({ row, key: keys[i] }))
      .filter(({ row }) => !rowSelection?.getCheckboxProps?.(row)?.disabled)
      .map(({ key }) => key);
    return { keys, enabledKeys };
  }, [dataSource, rowKey, rowSelection]);

  const selectedSet = useMemo(
    () => new Set(rowSelection?.selectedRowKeys ?? []),
    [rowSelection?.selectedRowKeys],
  );

  const allChecked =
    !!rowSelection &&
    pageMeta.enabledKeys.length > 0 &&
    pageMeta.enabledKeys.every((k) => selectedSet.has(k));
  const someChecked =
    !!rowSelection && pageMeta.enabledKeys.some((k) => selectedSet.has(k));

  const displayColumns = useMemo(() => {
    if (!rowSelection) return columns;

    const selectCol: NerveTableColumn<T> = {
      key: SELECT_COL_KEY,
      width: SELECT_COL_WIDTH,
      fixed: "left",
      className: "nerve-col-select",
      title: (
        <NerveCheckbox
          checked={allChecked}
          aria-label="全选本页"
          onChange={() => {
            const pageKeySet = new Set(pageMeta.keys);
            const kept = rowSelection.selectedRowKeys.filter((k) => !pageKeySet.has(k));
            if (allChecked) {
              const keys = kept;
              rowSelection.onChange(
                keys,
                dataSource.filter((row, i) => keys.includes(resolveRowKey(row, i, rowKey))),
              );
              return;
            }
            const keys = [...kept, ...pageMeta.enabledKeys];
            rowSelection.onChange(
              keys,
              dataSource.filter((row, i) => keys.includes(resolveRowKey(row, i, rowKey))),
            );
          }}
        />
      ),
      render: (row, index) => {
        const key = resolveRowKey(row, index, rowKey);
        const cb = rowSelection.getCheckboxProps?.(row);
        return (
          <NerveCheckbox
            aria-label="选择行"
            checked={selectedSet.has(key)}
            disabled={cb?.disabled}
            onChange={(e) => {
              const on = e.target.checked;
              const keys = on
                ? [...rowSelection.selectedRowKeys, key]
                : rowSelection.selectedRowKeys.filter((k) => k !== key);
              rowSelection.onChange(
                keys,
                dataSource.filter((r, i) => keys.includes(resolveRowKey(r, i, rowKey))),
              );
            }}
          />
        );
      },
    };
    return [selectCol, ...columns];
  }, [
    allChecked,
    columns,
    dataSource,
    pageMeta.enabledKeys,
    pageMeta.keys,
    rowKey,
    rowSelection,
    selectedSet,
  ]);

  const wrapRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = wrapRef.current?.querySelector<HTMLInputElement>(
      "th.nerve-col-select input[type='checkbox']",
    );
    if (!el) return;
    el.indeterminate = someChecked && !allChecked;
  }, [allChecked, someChecked]);

  const fixedOffsets = useMemo(() => buildFixedOffsets(displayColumns), [displayColumns]);
  const hasFixed = fixedOffsets.left.size > 0 || fixedOffsets.right.size > 0;

  // 默认铺满容器；scroll.x 仅作「过窄时横向滚动」的最小宽度，勿用 max-content 收缩列宽
  const tableStyle: CSSProperties | undefined =
    scroll?.x != null
      ? {
          width: "100%",
          minWidth: scroll.x,
        }
      : { width: "100%" };

  return (
    <div
      ref={wrapRef}
      className={cx(
        "nerve-table-wrap",
        (scroll?.x != null || hasFixed) && "nerve-table-wrap--scroll-x",
      )}
    >
      <table
        className={cx("nerve-table", "data-table", hasFixed && "nerve-table--fixed-cols", className)}
        style={tableStyle}
      >
        <thead>
          <tr>
            {displayColumns.map((c) => (
              <th key={c.key} className={columnClassName(c)} style={columnStyle(c, fixedOffsets)}>
                {c.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {dataSource.length === 0 ? (
            <tr className="nerve-table-empty-row">
              <td colSpan={displayColumns.length} className="nerve-table-empty-cell">
                <NerveEmpty sm description={emptyText} />
              </td>
            </tr>
          ) : (
            dataSource.map((row, i) => {
              const key = resolveRowKey(row, i, rowKey);
              return (
                <tr key={key} className={cx(selectedSet.has(key) && "nerve-table-row-selected")}>
                  {displayColumns.map((c) => {
                    const content = c.render
                      ? c.render(row, i)
                      : c.dataIndex
                        ? (row[c.dataIndex] as ReactNode)
                        : (row[c.key] as ReactNode);
                    return (
                      <td key={c.key} className={columnClassName(c)} style={columnStyle(c, fixedOffsets)}>
                        {content}
                      </td>
                    );
                  })}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

export type NerveTableActionItem = {
  key: string;
  label: ReactNode;
  variant?: NerveBtnVariant;
  danger?: boolean;
  primary?: boolean;
  onClick?: () => void;
  disabled?: boolean;
  /**
   * 最少勾选条数。默认 1（行操作）。
   * 设为 0：不校验勾选（如「添加」）。
   */
  minSelected?: number;
  /** 最多勾选条数；超出提示。不设则不限制。 */
  maxSelected?: number;
};

/** 预设动作可覆盖字段；未传则用默认 key / 文案 / 样式 / 勾选规则 */
export type NerveTableAddActionOptions = Omit<
  NerveTableActionItem,
  "key" | "label" | "primary" | "minSelected"
> &
  Partial<Pick<NerveTableActionItem, "key" | "label" | "primary" | "minSelected">>;

export type NerveTableDeleteActionOptions = Omit<
  NerveTableActionItem,
  "key" | "label" | "danger" | "minSelected"
> &
  Partial<Pick<NerveTableActionItem, "key" | "label" | "danger" | "minSelected">>;

/**
 * 表格工具栏「添加」预设：主色按钮、不要求勾选，默认文案「添加」。
 * 页面可改文案，例如 `nerveTableAddAction({ label: "登记节点", onClick })`。
 */
export function nerveTableAddAction(opts: NerveTableAddActionOptions): NerveTableActionItem {
  return {
    key: "add",
    label: "添加",
    primary: true,
    minSelected: 0,
    ...opts,
  };
}

/**
 * 表格工具栏「删除」预设：危险样式、至少勾选 1 条，默认文案「删除」。
 * 页面可改文案，例如 `nerveTableDeleteAction({ label: "移除", onClick })`。
 */
export function nerveTableDeleteAction(opts: NerveTableDeleteActionOptions): NerveTableActionItem {
  return {
    key: "delete",
    label: "删除",
    danger: true,
    variant: "danger",
    minSelected: 1,
    ...opts,
  };
}

export type NerveTableActionsProps = {
  actions: NerveTableActionItem[];
};

/** @deprecated 行内操作列已废弃；请用工具栏 `NerveTableToolbarActions` */
export function NerveTableActions({ actions }: NerveTableActionsProps) {
  return (
    <div className="nerve-table-actions">
      {actions.map((a) => (
        <NerveButton
          key={a.key}
          size="sm"
          variant={a.variant ?? "link"}
          className={cx(a.danger && "danger", a.primary && "nerve-action-primary")}
          disabled={a.disabled}
          onClick={a.onClick}
        >
          {a.label}
        </NerveButton>
      ))}
    </div>
  );
}

export type NerveTableToolbarActionsProps = {
  actions: NerveTableActionItem[];
  /**
   * 工具栏直接展示的按钮数；其余收入「…」菜单。
   * 默认 3：最多外露三个，超过才出现「…」。
   * 动作总数 ≤ maxInline 时不会出现「…」。
   */
  maxInline?: number;
  /** 当前勾选条数；用于点击时校验并提示，勿仅用 disabled 静默禁止 */
  selectedCount?: number;
};

async function guardSelection(
  action: NerveTableActionItem,
  selectedCount: number,
): Promise<boolean> {
  const min = action.minSelected ?? 1;
  const max = action.maxSelected;
  if (min > 0 && selectedCount < min) {
    await nerveResult({
      type: "info",
      title: "提示",
      message: min === 1 ? "请至少选择一条记录" : `请至少选择 ${min} 条记录`,
    });
    return false;
  }
  if (max != null && selectedCount > max) {
    await nerveResult({
      type: "info",
      title: "提示",
      message: max === 1 ? "请只选择一条记录" : `最多选择 ${max} 条记录`,
    });
    return false;
  }
  return true;
}

/** 表格右上角操作：未勾选点击会提示；超过 maxInline 个动作时用 … 展开。 */
export function NerveTableToolbarActions({
  actions,
  maxInline = 3,
  selectedCount = 0,
}: NerveTableToolbarActionsProps) {
  const visible = actions.filter(Boolean);
  const inlineCount = Math.max(0, maxInline);
  const inline = visible.slice(0, inlineCount);
  const rest = visible.slice(inlineCount);
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function runAction(a: NerveTableActionItem) {
    if (a.disabled) return;
    if (!(await guardSelection(a, selectedCount))) return;
    a.onClick?.();
  }

  if (!visible.length) return null;

  return (
    <div className="nerve-table-toolbar-actions" ref={rootRef}>
      {inline.map((a) => (
        <NerveButton
          key={a.key}
          size="sm"
          variant={a.variant ?? (a.primary ? "primary" : a.danger ? "danger" : "default")}
          className={cx(a.danger && "danger")}
          disabled={a.disabled}
          onClick={() => void runAction(a)}
        >
          {a.label}
        </NerveButton>
      ))}
      {rest.length > 0 ? (
        <div className="nerve-table-more">
          <NerveButton
            size="sm"
            className="nerve-table-more-trigger"
            disabled={rest.every((a) => a.disabled)}
            aria-haspopup="menu"
            aria-expanded={open}
            aria-controls={menuId}
            onClick={() => setOpen((v) => !v)}
          >
            …
          </NerveButton>
          {open ? (
            <ul id={menuId} className="nerve-table-more-menu" role="menu">
              {rest.map((a) => (
                <li key={a.key} role="none">
                  <button
                    type="button"
                    role="menuitem"
                    className={cx(
                      "nerve-table-more-item",
                      a.danger && "is-danger",
                      a.disabled && "is-disabled",
                    )}
                    disabled={a.disabled}
                    onClick={() => {
                      setOpen(false);
                      void runAction(a);
                    }}
                  >
                    {a.label}
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export const NERVE_COL_ACTIONS = "nerve-col-actions";
export const NERVE_COL_FIXED_LEFT = "nerve-col-fixed-left";
export const NERVE_COL_FIXED_RIGHT = "nerve-col-fixed-right";
export const NERVE_ALIGN_CENTER = "nerve-align-center";
export const NERVE_ALIGN_RIGHT = "nerve-align-right";

export type NerveThProps = ThHTMLAttributes<HTMLTableCellElement>;
export type NerveTdProps = TdHTMLAttributes<HTMLTableCellElement>;
export type NerveTableWrapProps = HTMLAttributes<HTMLDivElement>;
