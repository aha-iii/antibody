import type { ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NervePageHeaderProps = {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  className?: string;
};

export function NervePageHeader({ title, subtitle, actions, className }: NervePageHeaderProps) {
  return (
    <div className={cx("page-header", className)}>
      <div>
        <h2>{title}</h2>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {actions ? <div className="page-header-actions">{actions}</div> : null}
    </div>
  );
}

export type NerveTableToolbarProps = {
  /** 左侧：搜索、筛选等 */
  left?: ReactNode;
  /** 右侧：行操作（`NerveTableToolbarActions`）或自定义 */
  right?: ReactNode;
  /** 未传 left/right 时使用，兼容旧写法 */
  children?: ReactNode;
  className?: string;
};

/**
 * 表格工具栏：左搜索 / 右操作。
 * 有行内操作时：表格开启 `rowSelection`，操作放 `right={<NerveTableToolbarActions …/>}`，勿再做「操作」列。
 */
export function NerveTableToolbar({ left, right, children, className }: NerveTableToolbarProps) {
  if (left != null || right != null) {
    return (
      <div
        className={cx(
          "nerve-table-toolbar",
          "table-toolbar",
          "nerve-table-toolbar--split",
          className,
        )}
      >
        <div className="nerve-table-toolbar-left">{left}</div>
        <div className="nerve-table-toolbar-right">{right}</div>
      </div>
    );
  }
  return <div className={cx("nerve-table-toolbar", "table-toolbar", className)}>{children}</div>;
}

export type NerveSyncActionsProps = {
  children?: ReactNode;
  className?: string;
};

export function NerveSyncActions({ children, className }: NerveSyncActionsProps) {
  return <div className={cx("nerve-sync-actions", "sync-actions", className)}>{children}</div>;
}
