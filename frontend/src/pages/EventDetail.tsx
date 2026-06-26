import { useNavigate, useParams } from "react-router-dom";
import { useEvents } from "../hooks/useEvents";
import { useResolveEvent } from "../hooks/useResolveEvent";
import { formatClock, levelInfo } from "../lib/eventFmt";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="detail-field">
      <span className="detail-field-label">{label}</span>
      <span className="detail-field-val">{children}</span>
    </div>
  );
}

export default function EventDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: events = [] } = useEvents();
  const resolve = useResolveEvent();
  const evt = events.find((e) => e.event_id === id);

  if (!evt) {
    return (
      <div className="page">
        <button className="btn-back" onClick={() => navigate(-1)}>← Back</button>
        <div className="alert-empty">Event not found — it may have aged out of the live buffer.</div>
      </div>
    );
  }

  const { cls, label } = levelInfo(evt.wazuh_level);
  const isResolved = evt.status === "resolved";

  return (
    <div className="page">
      <div className="detail-topbar">
        <button className="btn-back" onClick={() => navigate(-1)}>← Back to alerts</button>
        {isResolved ? (
          <span className="badge low resolved-tag">✓ Resolved</span>
        ) : (
          <button
            className="btn-resolve lg"
            disabled={resolve.isPending}
            onClick={() => evt.event_id && resolve.mutate(evt.event_id, { onSuccess: () => navigate("/") })}
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
              <path d="M3 8.5l3.5 3.5L13 4.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Mark Resolved
          </button>
        )}
      </div>

      <div className="detail-head">
        <span className={`badge ${cls}`}>Level {evt.wazuh_level ?? "—"} · {label}</span>
        <h1 className="detail-title">{evt.rule_description ?? evt.event_type ?? "Security event"}</h1>
      </div>

      <div className="card sharp detail-grid">
        <Field label="Tenant">{evt.group ?? "unattributed"}</Field>
        <Field label="Agent">{evt.agent_name ?? "—"}{evt.agent_id ? ` (id ${evt.agent_id})` : ""}</Field>
        <Field label="Rule">{evt.rule_id ?? "—"}</Field>
        <Field label="MITRE">{evt.mitre_id?.length ? evt.mitre_id.join(", ") : "—"}{evt.mitre_tactic?.length ? ` · ${evt.mitre_tactic.join(", ")}` : ""}</Field>
        <Field label="Source IP">{evt.source_ip ?? "—"}</Field>
        <Field label="User">{evt.user ?? "—"}</Field>
        <Field label="First seen">{formatClock(evt.first_seen)}</Field>
        <Field label="Last seen">{formatClock(evt.last_seen)}</Field>
        <Field label="AI Severity">{evt.severity != null ? `${evt.severity}/100` : "—"}{evt.label ? ` · ${evt.label}` : ""}</Field>
        <Field label="Stage">{evt.status}</Field>
      </div>

      <div className="detail-cols">
        <div className="card sharp detail-panel">
          <p className="detail-panel-label">✦ LLM Explanation</p>
          <p className="detail-panel-text">{evt.explanation ?? "Not yet available — event is still processing."}</p>
        </div>
        <div className="card sharp detail-panel">
          <p className="detail-panel-label">⛨ Recommended Action</p>
          <p className="detail-panel-text">{evt.recommended_action ?? "Pending…"}</p>
        </div>
      </div>

      <div className="card sharp detail-panel">
        <p className="detail-panel-label">Triggering Logs{evt.trigger_logs?.length ? ` (${evt.trigger_logs.length})` : ""}</p>
        <pre className="detail-pre">{evt.trigger_logs?.length ? evt.trigger_logs.join("\n") : (evt.raw_log ?? "—")}</pre>
      </div>
    </div>
  );
}
