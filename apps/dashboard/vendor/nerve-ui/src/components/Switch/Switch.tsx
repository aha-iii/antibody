import type { InputHTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveSwitchProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  label?: ReactNode;
  sm?: boolean;
};

/** nerve-switch */
export function NerveSwitch(props: NerveSwitchProps) {
  const { label, sm, className, id, ...rest } = props;
  const sw = (
    <label className={cx("nerve-switch", "switch", sm && "switch-sm", className)}>
      <input type="checkbox" id={id} {...rest} />
      <span />
    </label>
  );
  if (label == null || label === "") return sw;
  return (
    <label className="nerve-switch-wrap switch-wrap">
      <span>{label}</span>
      {sw}
    </label>
  );
}
