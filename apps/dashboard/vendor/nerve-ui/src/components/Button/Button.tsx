import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveBtnVariant = "default" | "primary" | "danger" | "link";
export type NerveBtnSize = "md" | "sm";

export type NerveButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "type"> & {
  variant?: NerveBtnVariant;
  size?: NerveBtnSize;
  htmlType?: "button" | "submit" | "reset";
  /** 请求进行中：禁用按钮并加 loading 样式 */
  loading?: boolean;
  children?: ReactNode;
};

/** nerve-btn：对应原 Console btn() */
export function NerveButton({
  variant = "default",
  size = "md",
  htmlType = "button",
  loading = false,
  className,
  children,
  disabled,
  ...rest
}: NerveButtonProps) {
  return (
    <button
      type={htmlType}
      disabled={disabled || loading}
      className={cx(
        "nerve-btn",
        "ant-btn",
        variant === "primary" && "ant-btn-primary",
        variant === "danger" && "ant-btn-danger",
        variant === "link" && "ant-btn-link",
        size === "sm" && "ant-btn-sm",
        loading && "ant-btn-loading",
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}
