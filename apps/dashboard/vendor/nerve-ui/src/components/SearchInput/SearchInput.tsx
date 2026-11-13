import type { InputHTMLAttributes } from "react";
import { cx } from "../../utils/cx";

export type NerveSearchInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  width?: string | number;
};

/** nerve-search：表格工具栏搜索框 */
export function NerveSearchInput(props: NerveSearchInputProps) {
  const {
  width = 220,
  className,
  placeholder = "搜索…",
  style,
  ...rest
} = props;
  const w = typeof width === "number" ? `${width}px` : width;
  return (
    <input
      type="search"
      className={cx("nerve-input", "nerve-search", "ant-input", className)}
      placeholder={placeholder}
      style={{ width: w, ...style }}
      {...rest}
    />
  );
}
