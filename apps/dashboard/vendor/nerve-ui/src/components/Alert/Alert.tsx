import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveAlertTone = "info" | "error" | "success" | "warning";

export type NerveAlertProps = HTMLAttributes<HTMLDivElement> & {
  tone?: NerveAlertTone;
  children?: ReactNode;
};

/** nerve-alert */
export function NerveAlert({ tone = "info", className, children, ...rest }: NerveAlertProps) {
  return (
    <div className={cx("nerve-alert", "ant-alert", `ant-alert-${tone}`, className)} {...rest}>
      {children}
    </div>
  );
}
