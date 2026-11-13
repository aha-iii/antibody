import type { SelectHTMLAttributes } from "react";
import { cx } from "../../utils/cx";

export type NerveSelectOption = {
  value: string;
  label: string;
  disabled?: boolean;
};

export type NerveSelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "children"> & {
  options: NerveSelectOption[];
  wide?: boolean;
};

/** nerve-select：对应原 Console select() */
export function NerveSelect(props: NerveSelectProps) {
  const { options, wide, className, ...rest } = props;
  return (
    <select className={cx("nerve-select", "ant-input", wide && "ant-input-wide", className)} {...rest}>
      {options.map((o) => (
        <option key={o.value} value={o.value} disabled={o.disabled}>
          {o.label}
        </option>
      ))}
    </select>
  );
}
