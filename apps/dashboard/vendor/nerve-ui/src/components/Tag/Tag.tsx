import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveTagTone = "default" | "green" | "red" | "orange" | "blue";

export type NerveTagProps = HTMLAttributes<HTMLSpanElement> & {
  tone?: NerveTagTone;
  children?: ReactNode;
};

/** nerve-tag */
export function NerveTag({ tone = "default", className, children, ...rest }: NerveTagProps) {
  return (
    <span
      className={cx(
        "nerve-tag",
        "ant-tag",
        tone !== "default" && `ant-tag-${tone}`,
        className,
      )}
      {...rest}
    >
      {children}
    </span>
  );
}
