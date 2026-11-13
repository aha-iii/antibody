import type { ReactNode } from "react";
import { cx } from "../../utils/cx";

export type NerveTabItem = {
  id: string;
  label: ReactNode;
};

export type NerveTabBarProps = {
  tabs: NerveTabItem[];
  activeId: string;
  onChange: (id: string) => void;
  className?: string;
};

/** nerve-tab-bar */
export function NerveTabBar({ tabs, activeId, onChange, className }: NerveTabBarProps) {
  return (
    <div className={cx("nerve-tab-bar", "tab-bar", className)} role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={t.id === activeId}
          className={cx("tab-btn", t.id === activeId && "active")}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
