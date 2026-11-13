import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveEmptyProps = HTMLAttributes<HTMLDivElement> & {
  description?: ReactNode;
  hint?: ReactNode;
  sm?: boolean;
};

const EMPTY_SVG = (
  <svg
    className="ant-empty-img"
    viewBox="0 0 64 41"
    width="64"
    height="41"
    aria-hidden
    focusable="false"
  >
    <g fill="none" fillRule="evenodd">
      <g transform="translate(0 1)">
        <ellipse fill="#f5f5f5" cx="32" cy="33" rx="32" ry="7" />
        <g fillRule="nonzero" stroke="#d9d9d9">
          <path d="M55 12.76L44.854 1.258C44.367.474 43.656 0 42.907 0H21.093c-.749 0-1.46.474-1.947 1.257L9 12.761V22h46v-9.24z" />
          <path
            fill="#fafafa"
            d="M41.613 15.931c0-1.605.994-2.93 2.227-2.931H55v18.137C55 33.26 53.68 35 52.05 35h-40.1C10.32 35 9 33.259 9 31.137V13h11.16c1.233 0 2.227 1.323 2.227 2.928v.022c0 1.605 1.005 2.901 2.237 2.901h14.752c1.232 0 2.237-1.308 2.237-2.913v-.007z"
            stroke="none"
          />
        </g>
      </g>
    </g>
  </svg>
);

/** ant-empty / nerve 空状态，带图标 */
export function NerveEmpty({
  description = "暂无数据",
  hint,
  sm,
  className,
  ...rest
}: NerveEmptyProps) {
  return (
    <div className={cx("ant-empty", sm && "ant-empty-sm", className)} {...rest}>
      <div className="ant-empty-image">{EMPTY_SVG}</div>
      <div className="ant-empty-description">{description}</div>
      {hint != null && hint !== "" ? <p className="ant-empty-hint">{hint}</p> : null}
    </div>
  );
}
