import type { InputHTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveCheckboxProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  label?: ReactNode;
};

export function NerveCheckbox(props: NerveCheckboxProps) {
  const { label, className, ...rest } = props;
  const input = <input type="checkbox" className={cx("nerve-checkbox", className)} {...rest} />;
  if (label == null || label === "") return input;
  return (
    <label className="nerve-checkbox-wrap">
      {input}
      <span>{label}</span>
    </label>
  );
}
