import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveCardProps = HTMLAttributes<HTMLDivElement> & {
  title: ReactNode;
  tip?: ReactNode;
  bodyId?: string;
  children?: ReactNode;
};

/** nerve-card + ant-card */
export function NerveCard({ title, tip, bodyId, className, children, ...rest }: NerveCardProps) {
  return (
    <div className={cx("nerve-card", "ant-card", className)} {...rest}>
      <div className="ant-card-head">
        {title}
        {tip != null && tip !== "" ? <span className="head-tip">{tip}</span> : null}
      </div>
      <div className="ant-card-body" id={bodyId}>
        {children}
      </div>
    </div>
  );
}

export type NervePanelCardProps = HTMLAttributes<HTMLDivElement> & {
  title: ReactNode;
  children?: ReactNode;
};

/** 轻量 panel 卡片 */
export function NervePanelCard({ title, className, children, ...rest }: NervePanelCardProps) {
  return (
    <div className={cx("nerve-panel-card", "card", className)} {...rest}>
      <h3>{title}</h3>
      <div>{children}</div>
    </div>
  );
}
