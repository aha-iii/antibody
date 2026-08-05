import type { ReactNode } from "react";
import { DASHBOARD_BUILD, NAV, PAGE_META, type PageId } from "../nav";

type Props = {
  page: PageId;
  onNavigate: (id: PageId) => void;
  healthText?: string;
  healthOk?: boolean;
  username?: string | null;
  onLogout?: () => void;
  children: ReactNode;
};

export function DashboardLayout({
  page,
  onNavigate,
  healthText,
  healthOk,
  username,
  onLogout,
  children,
}: Props) {
  const meta = PAGE_META[page];
  let lastGroup = "";

  return (
    <div className="console-layout">
      <aside className="console-sider">
        <div className="sider-logo">
          <div className="logo-icon">E</div>
          <div>
            <strong>Nerve Native</strong>
            <small>Expert Dashboard · @nerve/ui</small>
          </div>
        </div>
        <nav className="sider-menu">
          {NAV.map((item) => {
            const showGroup = item.group !== lastGroup;
            lastGroup = item.group;
            return (
              <div key={item.id}>
                {showGroup ? (
                  <div className="menu-group-title">{item.group}</div>
                ) : null}
                <button
                  type="button"
                  className={`menu-item${page === item.id ? " active" : ""}`}
                  onClick={() => onNavigate(item.id)}
                >
                  <span className="menu-icon">{item.icon}</span>
                  <span className="menu-label">{item.label}</span>
                </button>
              </div>
            );
          })}
        </nav>
        <div className="sider-foot">build {DASHBOARD_BUILD}</div>
      </aside>

      <div className="console-main">
        <header className="console-topbar">
          <div className="topbar-left">
            <div className="topbar-title">{meta.title}</div>
            <div className="topbar-sub muted small">{meta.subtitle}</div>
          </div>
          <div className="topbar-right">
            <span
              className={`health-pill${healthOk === true ? " ok" : healthOk === false ? " err" : ""}`}
            >
              <span className="health-dot" />
              {healthText || "connecting…"}
            </span>
            {username ? <span className="muted small">{username}</span> : null}
            {onLogout ? (
              <button type="button" className="ant-btn ant-btn-sm" onClick={onLogout}>
                退出
              </button>
            ) : null}
          </div>
        </header>
        <main className="console-content page-inner">{children}</main>
      </div>
    </div>
  );
}
