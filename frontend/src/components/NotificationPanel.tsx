// The slide-out panel that opens from the bell in the header. Lists the current
// notifications and lets the user dismiss one or clear them all. The parent
// (AppLayout) owns the data and the open/closed state; this just draws it.

import type { Notification, NotificationType } from "../types/notification";

const TYPE_COLOR: Record<NotificationType, string> = {
  critical: "var(--severity-critical)",
  warning:  "var(--severity-high)",
  playbook: "var(--accent-blue)",
  info:     "var(--text-muted)",
};

const TYPE_LABEL: Record<NotificationType, string> = {
  critical: "Critical",
  warning:  "Warning",
  playbook: "Playbook",
  info:     "Info",
};

interface Props {
  open: boolean;
  notifications: Notification[];
  onDismiss: (id: string) => void;
  onClearAll: () => void;
  onClose: () => void;
}

export default function NotificationPanel({ open, notifications, onDismiss, onClearAll, onClose }: Props) {
  return (
    <>
      {open && <div className="notif-backdrop" onClick={onClose} />}
      <aside className={`notif-panel ${open ? "open" : ""}`}>
        <div className="notif-header">
          <div className="notif-header-left">
            <h2 className="notif-title">Notifications</h2>
            {notifications.length > 0 && (
              <span className="notif-count">{notifications.length}</span>
            )}
          </div>
          {notifications.length > 0 && (
            <button className="notif-clear" onClick={onClearAll}>Clear all</button>
          )}
        </div>

        <div className="notif-list">
          {notifications.length === 0 ? (
            <div className="notif-empty">
              <span className="notif-empty-icon">&#10003;</span>
              <p className="notif-empty-title">All caught up</p>
              <p className="notif-empty-sub">No new activity since your last session.</p>
            </div>
          ) : (
            notifications.map((notif) => (
              <div key={notif.id} className="notif-item">
                <span className="notif-dot" style={{ background: TYPE_COLOR[notif.type] }} />
                <div className="notif-item-body">
                  <div className="notif-item-meta">
                    <span className="notif-type" style={{ color: TYPE_COLOR[notif.type] }}>
                      {TYPE_LABEL[notif.type]}
                    </span>
                    <span className="notif-time">{notif.time}</span>
                  </div>
                  <div className="notif-item-title">{notif.title}</div>
                  <div className="notif-item-desc">{notif.description}</div>
                </div>
                <button className="notif-dismiss" onClick={() => onDismiss(notif.id)} aria-label="Dismiss">
                  &#215;
                </button>
              </div>
            ))
          )}
        </div>
      </aside>
    </>
  );
}
