import type { InputHTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveRadioProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  label: ReactNode;
};

export function NerveRadio({ label, className, ...rest }: NerveRadioProps) {
  return (
    <label className="nerve-radio-wrap">
      <input type="radio" className={cx("nerve-radio", className)} {...rest} />
      <span>{label}</span>
    </label>
  );
}
