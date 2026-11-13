import { useEffect, useState } from "react";
import { NerveSelect } from "../Select";
import { NerveButton } from "../Button";
import { NerveInput } from "../Input";
import { cx } from "../../utils/cx";

export const PAGE_SIZE_OPTIONS = [5, 10, 20, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 10;

export type NervePaginationState = { page: number; pageSize: number };

export function paginate<T>(items: T[], page: number, pageSize: number): T[] {
  const start = (page - 1) * pageSize;
  return items.slice(start, start + pageSize);
}

export function paginationTotalPages(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(Math.max(total, 1) / pageSize));
}

export function clampPage(page: number, total: number, pageSize: number): number {
  const pages = paginationTotalPages(total, pageSize);
  return Math.min(Math.max(1, page), pages);
}

export function defaultPaginationState(pageSize = DEFAULT_PAGE_SIZE): NervePaginationState {
  return { page: 1, pageSize };
}

export type NervePaginationProps = {
  total: number;
  page: number;
  pageSize: number;
  onChange: (next: NervePaginationState) => void;
  className?: string;
};

/** 分页条：每页条数 + 上一页/下一页 + 第几页 + 跳转，默认 10 条/页 */
export function NervePagination({
  total,
  page,
  pageSize,
  onChange,
  className,
}: NervePaginationProps) {
  const pages = paginationTotalPages(total, pageSize);
  const safePage = clampPage(page, total, pageSize);
  const from = total === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const to = Math.min(safePage * pageSize, total);
  const [jumpDraft, setJumpDraft] = useState(String(safePage));

  useEffect(() => {
    setJumpDraft(String(safePage));
  }, [safePage]);

  const commitJump = () => {
    const n = Number(jumpDraft);
    if (!Number.isFinite(n)) {
      setJumpDraft(String(safePage));
      return;
    }
    const next = clampPage(Math.trunc(n), total, pageSize);
    setJumpDraft(String(next));
    if (next !== safePage) onChange({ page: next, pageSize });
  };

  return (
    <div className={cx("nerve-pagination", "table-pagination", "pagination-bar", className)}>
      <span className="muted">
        显示 {from}–{to}，共 {total} 条
      </span>
      <div className="table-pagination-actions">
        <label className="muted page-size-label">
          每页
          <NerveSelect
            value={String(pageSize)}
            options={PAGE_SIZE_OPTIONS.map((n) => ({ value: String(n), label: String(n) }))}
            onChange={(e) =>
              onChange({ page: 1, pageSize: Number(e.target.value) || DEFAULT_PAGE_SIZE })
            }
            className="page-size-select"
            style={{ width: 72, marginLeft: 4 }}
          />
        </label>
        <NerveButton
          size="sm"
          disabled={safePage <= 1}
          onClick={() => onChange({ page: safePage - 1, pageSize })}
        >
          上一页
        </NerveButton>
        <span className="muted page-indicator">
          第 {safePage} / {pages} 页
        </span>
        <NerveButton
          size="sm"
          disabled={safePage >= pages}
          onClick={() => onChange({ page: safePage + 1, pageSize })}
        >
          下一页
        </NerveButton>
        <label className="muted page-jump">
          跳至
          <NerveInput
            sm
            className="page-jump-input"
            value={jumpDraft}
            inputMode="numeric"
            aria-label="跳至页码"
            onChange={(e) => setJumpDraft(e.target.value)}
            onBlur={commitJump}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                commitJump();
              }
            }}
          />
          页
        </label>
      </div>
    </div>
  );
}
