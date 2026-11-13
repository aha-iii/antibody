import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { cx } from "../../utils/cx";

export type NerveMenuLeaf = {
  type: "item";
  id: string;
  label: string;
  icon?: string;
  nested?: boolean;
};

export type NerveSubMenu = {
  type: "submenu";
  key: string;
  title: string;
  icon?: string;
  items: NerveMenuLeaf[];
};

export type NerveMenuGroup = {
  title: string;
  entries: Array<NerveMenuLeaf | NerveSubMenu>;
};

export type FlatSiderNavItem<T extends string = string> = {
  id: T;
  label: string;
  icon: string;
  group: string;
  subgroup?: string;
  nested?: boolean;
};

/** 扁平 NAV 配置 → 分组 + 可折叠子菜单 */
export function buildSiderMenuGroups<T extends string>(
  items: FlatSiderNavItem<T>[],
): NerveMenuGroup[] {
  const groups: NerveMenuGroup[] = [];
  let currentGroup: NerveMenuGroup | null = null;
  let currentSubmenu: NerveSubMenu | null = null;

  for (const item of items) {
    if (!currentGroup || currentGroup.title !== item.group) {
      currentGroup = { title: item.group, entries: [] };
      groups.push(currentGroup);
      currentSubmenu = null;
    }

    if (item.subgroup) {
      const submenuKey = `${item.group}::${item.subgroup}`;
      if (!currentSubmenu || currentSubmenu.key !== submenuKey) {
        currentSubmenu = {
          type: "submenu",
          key: submenuKey,
          title: item.subgroup,
          icon: undefined,
          items: [],
        };
        currentGroup.entries.push(currentSubmenu);
      }
      currentSubmenu.items.push({
        type: "item",
        id: item.id,
        label: item.label,
        icon: item.icon,
        nested: false,
      });
      if (!currentSubmenu.icon) {
        currentSubmenu.icon = item.icon;
      }
    } else {
      currentSubmenu = null;
      currentGroup.entries.push({
        type: "item",
        id: item.id,
        label: item.label,
        icon: item.icon,
      });
    }
  }

  return groups;
}

function submenuContainsActive(submenu: NerveSubMenu, activeId: string): boolean {
  return submenu.items.some((item) => item.id === activeId);
}

export type NerveMenuProps = {
  groups: NerveMenuGroup[];
  activeId: string;
  onSelect: (id: string) => void;
  className?: string;
};

export function NerveMenu({ groups, activeId, onSelect, className }: NerveMenuProps) {
  const autoExpanded = useMemo(() => {
    const keys = new Set<string>();
    for (const group of groups) {
      for (const entry of group.entries) {
        if (entry.type === "submenu" && submenuContainsActive(entry, activeId)) {
          keys.add(entry.key);
        }
      }
    }
    return keys;
  }, [groups, activeId]);

  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(autoExpanded));

  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev);
      for (const key of autoExpanded) next.add(key);
      return next;
    });
  }, [autoExpanded]);

  const toggleSubmenu = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  return (
    <nav className={cx("nerve-sider-menu", className)}>
      {groups.map((group) => (
        <div key={group.title} className="nerve-sider-menu-group">
          <div className="nerve-sider-menu-group-title">{group.title}</div>
          {group.entries.map((entry) => {
            if (entry.type === "item") {
              return (
                <MenuItem
                  key={entry.id}
                  item={entry}
                  active={activeId === entry.id}
                  onSelect={onSelect}
                />
              );
            }
            const open = expanded.has(entry.key);
            const submenuActive = submenuContainsActive(entry, activeId);
            return (
              <div
                key={entry.key}
                className={cx("nerve-sider-submenu", open && "is-open", submenuActive && "has-active")}
              >
                <div className="nerve-sider-submenu-head">
                  <button
                    type="button"
                    className="nerve-sider-submenu-head-main"
                    aria-expanded={open}
                    onClick={() => toggleSubmenu(entry.key)}
                  >
                    {entry.icon ? <span className="nerve-sider-menu-icon">{entry.icon}</span> : null}
                    <span className="nerve-sider-menu-label">{entry.title}</span>
                  </button>
                  <button
                    type="button"
                    className="nerve-sider-submenu-arrow-btn"
                    aria-expanded={open}
                    aria-label={open ? "收起子菜单" : "展开子菜单"}
                    onClick={() => toggleSubmenu(entry.key)}
                  >
                    <span className="nerve-sider-submenu-arrow" aria-hidden>
                      ▸
                    </span>
                  </button>
                </div>
                {open ? (
                  <div className="nerve-sider-submenu-body">
                    {entry.items.map((item) => (
                      <MenuItem
                        key={item.id}
                        item={item}
                        active={activeId === item.id}
                        nested
                        onSelect={onSelect}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      ))}
    </nav>
  );
}

function MenuItem({
  item,
  active,
  nested = false,
  onSelect,
}: {
  item: NerveMenuLeaf;
  active: boolean;
  nested?: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      className={cx(
        "nerve-sider-menu-item",
        nested && "is-nested",
        active && "is-active",
      )}
      onClick={() => onSelect(item.id)}
    >
      {item.icon ? <span className="nerve-sider-menu-icon">{item.icon}</span> : null}
      <span className="nerve-sider-menu-label">{item.label}</span>
    </button>
  );
}

export type NerveSiderProps = {
  logo?: ReactNode;
  title?: string;
  subtitle?: string;
  foot?: ReactNode;
  menu: NerveMenuGroup[];
  activeMenuId: string;
  onMenuSelect: (id: string) => void;
  className?: string;
};

/** 左侧栏（Logo + 可折叠菜单 + 底部 slot） */
export function NerveSider({
  logo,
  title = "Nerve",
  subtitle,
  foot,
  menu,
  activeMenuId,
  onMenuSelect,
  className,
}: NerveSiderProps) {
  return (
    <aside className={cx("nerve-sider", className)}>
      <div className="nerve-sider-logo">
        {logo ?? <div className="nerve-sider-logo-icon">N</div>}
        <div>
          <strong>{title}</strong>
          {subtitle ? <small>{subtitle}</small> : null}
        </div>
      </div>
      <NerveMenu groups={menu} activeId={activeMenuId} onSelect={onMenuSelect} />
      {foot ? <div className="nerve-sider-foot">{foot}</div> : null}
    </aside>
  );
}
