import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveFormProps = HTMLAttributes<HTMLDivElement> & {
  children?: ReactNode;
};

/** nerve-form：垂直表单容器，对应 formStack() */
export function NerveForm({ className, children, ...rest }: NerveFormProps) {
  return (
    <div className={cx("nerve-form", "form-stack", className)} {...rest}>
      {children}
    </div>
  );
}

export type NerveFormItemProps = HTMLAttributes<HTMLDivElement> & {
  label?: ReactNode;
  /** 必填标记，在 label 后显示 * */
  required?: boolean;
  children?: ReactNode;
};

/** nerve-form-item */
export function NerveFormItem({ label, required, className, children, ...rest }: NerveFormItemProps) {
  return (
    <div className={cx("nerve-form-item", "ant-form-item", className)} {...rest}>
      {label != null && label !== "" ? (
        <label className="nerve-form-label ant-form-label">
          {label}
          {required ? <span className="nerve-form-required"> *</span> : null}
        </label>
      ) : null}
      {children}
    </div>
  );
}
