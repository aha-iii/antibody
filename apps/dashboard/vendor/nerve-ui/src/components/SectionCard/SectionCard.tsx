import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveSectionCardProps = HTMLAttributes<HTMLDivElement> & {
  title: ReactNode;
  subtitle?: ReactNode;
  count?: ReactNode;
  children?: ReactNode;
};

/** nerve-section-card：规则库等分区卡片 */
export function NerveSectionCard({
  title,
  subtitle,
  count,
  className,
  children,
  ...rest
}: NerveSectionCardProps) {
  return (
    <div className={cx("nerve-section-card", "cr-section", "card", className)} {...rest}>
      <div className="nerve-section-head cr-section-head">
        <div>
          <h3>{title}</h3>
          {subtitle != null && subtitle !== "" ? (
            <p className="muted small">{subtitle}</p>
          ) : null}
        </div>
        {count != null ? <span className="nerve-section-count cr-section-count">{count}</span> : null}
      </div>
      <div className="nerve-section-body">{children}</div>
    </div>
  );
}
