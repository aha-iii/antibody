import type { TextareaHTMLAttributes } from "react";
import { cx } from "../../utils/cx";

export type NerveTextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  /** 默认 true，与原 Console textarea() 一致 */
  wide?: boolean;
};

/** nerve-textarea */
export function NerveTextarea(props: NerveTextareaProps) {
  const { wide = true, className, ...rest } = props;
  return (
    <textarea
      className={cx(
        "nerve-input",
        "nerve-textarea",
        "ant-input",
        wide !== false && "ant-input-wide",
        className,
      )}
      {...rest}
    />
  );
}
