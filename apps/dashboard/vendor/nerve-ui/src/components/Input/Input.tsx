import type { InputHTMLAttributes } from "react";
import { cx } from "../../utils/cx";

export type NerveInputProps = InputHTMLAttributes<HTMLInputElement> & {
  wide?: boolean;
  sm?: boolean;
};

/** nerve-input：对应原 Console input() */
export function NerveInput(props: NerveInputProps) {
  const { wide, sm, className, ...rest } = props;
  return (
    <input
      className={cx("nerve-input", "ant-input", wide && "ant-input-wide", sm && "sm", className)}
      {...rest}
    />
  );
}
