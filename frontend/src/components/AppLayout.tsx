import { useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useEvents } from "../hooks/useEvents";
import NotificationPanel from "./NotificationPanel";
import { levelInfo } from "../lib/eventFmt";
import type { Notification } from "../types/notification";

export interface OutletCtx {
  search: string;
}

// Derive lightweight notifications from the most severe recent events.
function useDerivedNotifications(): Notification[] {
  const { data: events = [] } = useEvents();
  return useMemo(() => {
    return [...events]
      .reverse()
      .filter((e) => (e.wazuh_level ?? 0) >= 10)
      .slice(0, 12)
      .map((e) => {
        const { cls } = levelInfo(e.wazuh_level);
        return {
          id: e.event_id ?? `${e.timestamp}`,
          type: cls === "critical" ? "critical" : "warning",
          title: e.rule_description ?? e.event_type ?? "Security event",
          description: `${e.group ?? "unattributed"} · ${e.agent_name ?? "agent"}`,
          time: e.last_seen?.slice(11, 19) ?? "",
        } as Notification;
      });
  }, [events]);
}

function NavIcon({ d }: { d: string }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path d={d} stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  // Search is URL-backed (?q=) so tenant nodes on the radar can deep-link into
  // Active Alerts pre-filtered, and the filter survives refresh/sharing.
  const [searchParams, setSearchParams] = useSearchParams();
  const search = searchParams.get("q") ?? "";
  const setSearch = (value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value) next.set("q", value);
    else next.delete("q");
    setSearchParams(next, { replace: true });
  };
  const [notifOpen, setNotifOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const menuRef = useRef<HTMLDivElement>(null);

  const allNotifs = useDerivedNotifications();
  const notifications = allNotifs.filter((n) => !dismissed.has(n.id));

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const initial = (user?.username ?? "?").charAt(0).toUpperCase();

  return (
    <div className="shell">
      {/* Sidebar */}
      <aside className="shell-sidebar">
        <div className="shell-brand">
          <span className="shell-brand-mark">▣</span> SOC
        </div>
        <nav className="shell-nav">
          <NavLink to="/" end className={({ isActive }) => `shell-nav-item ${isActive ? "active" : ""}`}>
            <NavIcon d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM8 5v3l2 1.5M8 1.5V3m0 10v1.5M14.5 8H13M3 8H1.5" />
            Dashboard
          </NavLink>
          <NavLink to="/alerts" className={({ isActive }) => `shell-nav-item ${isActive ? "active" : ""}`}>
            <NavIcon d="M8 1.5A4.5 4.5 0 0 0 3.5 6v2.5L2 11h12l-1.5-2.5V6A4.5 4.5 0 0 0 8 1.5zM6.5 11a1.5 1.5 0 0 0 3 0" />
            Active Alerts
          </NavLink>
          <NavLink to="/tenants" className={({ isActive }) => `shell-nav-item ${isActive ? "active" : ""}`}>
            <NavIcon d="M2 13V9l4-2 4 2v4M6 7V3l4-2 4 2v10" />
            Tenants
          </NavLink>
        </nav>
        <div className="shell-sidebar-foot">
          <span className="shell-avatar sm">{initial}</span>
          <div className="shell-user-meta">
            <span className="shell-user-name">{user?.username ?? "Analyst"}</span>
            <span className="shell-user-role">SOC Team</span>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="shell-main">
        <header className="shell-header">
          <div className="shell-search">
            <span className="shell-search-icon">⌕</span>
            <input
              className="shell-search-input"
              placeholder="Search alerts — tenant, host, IP, user, rule, MITRE…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <button className="shell-search-clear" onClick={() => setSearch("")} aria-label="Clear search">×</button>
            )}
          </div>

          <div className="shell-header-right">
            <button className="shell-bell" onClick={() => setNotifOpen((o) => !o)} aria-label="Notifications">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
                <path d="M8 1.5A4.5 4.5 0 0 0 3.5 6v2.5L2 11h12l-1.5-2.5V6A4.5 4.5 0 0 0 8 1.5z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
                <path d="M6.5 11a1.5 1.5 0 0 0 3 0" stroke="currentColor" strokeWidth="1.4" />
              </svg>
              {notifications.length > 0 && <span className="shell-bell-badge">{notifications.length}</span>}
            </button>

            <div className="shell-usermenu" ref={menuRef}>
              <button className="shell-avatar-btn" onClick={() => setMenuOpen((o) => !o)} aria-label="User menu">
                <span className="shell-avatar">{initial}</span>
              </button>
              {menuOpen && (
                <div className="shell-menu">
                  <div className="shell-menu-head">
                    <span className="shell-menu-name">{user?.username ?? "Analyst"}</span>
                    <span className="shell-menu-sub">SOC Team</span>
                  </div>
                  <button className="shell-menu-item" disabled>Profile</button>
                  <button className="shell-menu-item" disabled>Settings</button>
                  <div className="shell-menu-divider" />
                  <button
                    className="shell-menu-item danger"
                    onClick={() => { logout(); navigate("/login"); }}
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="shell-content">
          <Outlet context={{ search } satisfies OutletCtx} />
        </main>
      </div>

      <NotificationPanel
        open={notifOpen}
        notifications={notifications}
        onDismiss={(id) => setDismissed((s) => new Set(s).add(id))}
        onClearAll={() => setDismissed(new Set(allNotifs.map((n) => n.id)))}
        onClose={() => setNotifOpen(false)}
      />
    </div>
  );
}
