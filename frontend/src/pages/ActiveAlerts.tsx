import { useMemo, useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import { useEvents } from "../hooks/useEvents";
import { useResolveEvent } from "../hooks/useResolveEvent";
import type { SOCEvent } from "../types/event";
import type { OutletCtx } from "../components/AppLayout";
import { formatAgo, formatClock, levelInfo, matchesSearch, SEV_COLOR } from "../lib/eventFmt";

function AlertCard({ evt }: { evt: SOCEvent }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const resolve = useResolveEvent();
  const { cls, label } = levelInfo(evt.wazuh_level);
  const correlated = evt.trigger_logs?.length ?? 0;

  return (
    <div className={`alert-card alert-${cls} ${open ? "open" : ""}`} style={{ borderLeftColor: SEV_COLOR[cls] }}>
      <div className="alert-row">
        {/* Severity */}
        <div className="alert-sev">
          <span className={`badge ${cls}`}>Level {evt.wazuh_level ?? "—"}</span>
          <span className="alert-sev-label">{label}</span>
        </div>

        {/* Main */}
        <div className="alert-main">
          <span className="alert-title">{evt.rule_description ?? evt.event_type ?? "Security event"}</span>
          <span className="alert-meta">
            <span className="alert-tenant">{evt.group ?? "unattributed"}</span>
            <span className="alert-sep">·</span>
            {evt.agent_name ?? "unknown host"}
            {evt.user ? <><span className="alert-sep">·</span>{evt.user}</> : null}
            {evt.mitre_id?.length ? <span className="alert-mitre">{evt.mitre_id.join(", ")}</span> : null}
          </span>
        </div>

        {/* Correlated */}
        <div className="alert-corr">
          <span className="alert-corr-num">{correlated}</span>
          <span className="alert-corr-label">correlated</span>
        </div>

        {/* Times */}
        <div className="alert-times">
          <div className="alert-time">
            <span className="alert-time-label">First seen</span>
            <span className="alert-time-val">{formatClock(evt.first_seen)}</span>
            <span className="alert-time-ago">{formatAgo(evt.first_seen)}</span>
          </div>
          <div className="alert-time">
            <span className="alert-time-label">Last seen</span>
            <span className="alert-time-val">{formatClock(evt.last_seen)}</span>
            <span className="alert-time-ago">{formatAgo(evt.last_seen)}</span>
          </div>
        </div>

        {/* Actions */}
        <div className="alert-actions">
          <button
            className="btn-resolve"
            disabled={resolve.isPending}
            onClick={() => evt.event_id && resolve.mutate(evt.event_id)}
            title="Mark resolved"
          >
            <svg width="13" height="13" viewBox="0 0 16 16" fill="none">
              <path d="M3 8.5l3.5 3.5L13 4.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Resolve
          </button>
          <button className="btn-view" onClick={() => evt.event_id && navigate(`/alerts/${encodeURIComponent(evt.event_id)}`)}>
            View
          </button>
          <button className={`alert-expand ${open ? "open" : ""}`} onClick={() => setOpen((o) => !o)} aria-label="Expand">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
              <path d="M4 6l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
        </div>
      </div>

      {open && (
        <div className="alert-expanded">
          <div className="alert-expanded-col">
            <p className="alert-expanded-label">✦ LLM Explanation</p>
            <p className="alert-expanded-text">
              {evt.explanation ??
                (evt.status === "explained" ? "—" : "Generating analysis…")}
            </p>
          </div>
          <div className="alert-expanded-col">
            <p className="alert-expanded-label">⛨ Recommended Action</p>
            <p className="alert-expanded-text">{evt.recommended_action ?? "Pending…"}</p>
            <button className="btn-primary sharp" disabled>Take Action</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ActiveAlerts() {
  const { search } = useOutletContext<OutletCtx>();
  const { data: events = [], isFetching } = useEvents();

  const alerts = useMemo(() => {
    return events
      .filter((e) => e.status !== "resolved")
      .filter((e) => matchesSearch(e, search))
      .sort((a, b) => {
        const lvl = (b.wazuh_level ?? 0) - (a.wazuh_level ?? 0);
        if (lvl !== 0) return lvl;
        return Date.parse(b.last_seen ?? "") - Date.parse(a.last_seen ?? "");
      });
  }, [events, search]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Active Alerts</h1>
          <p className="page-sub">Showing active security events requiring your attention.</p>
        </div>
        <div className="page-head-right">
          {isFetching && <span className="page-refresh">Refreshing…</span>}
          <span className="page-count">{alerts.length} alerts</span>
        </div>
      </div>

      <div className="alert-list">
        {alerts.length === 0 ? (
          <div className="alert-empty">
            {search ? `No alerts match “${search}”.` : "Waiting for events from the pipeline…"}
          </div>
        ) : (
          alerts.map((evt) => <AlertCard key={evt.event_id ?? evt.timestamp} evt={evt} />)
        )}
      </div>
    </div>
  );
}
