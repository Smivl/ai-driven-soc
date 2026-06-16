import { useMemo } from "react";
import { useTenants } from "../hooks/useTenants";
import { useUpdateTenant } from "../hooks/useUpdateTenant";
import { useEvents } from "../hooks/useEvents";
import type { Tenant } from "../types/tenant";

const LEVELS = Array.from({ length: 16 }, (_, i) => i); // 0..15

function TenantCard({ tenant, events, highEvents }: { tenant: Tenant; events: number; highEvents: number }) {
  const update = useUpdateTenant();

  return (
    <div className="card sharp tenant-card">
      <div className="tenant-card-head">
        <span className="tenant-card-name">{tenant.company}</span>
        <span className="tenant-group-tag">{tenant.group}</span>
      </div>

      <div className="tenant-card-stats">
        <span><strong>{tenant.agents.length}</strong> agents</span>
        <span><strong>{events}</strong> events</span>
        {highEvents > 0 && <span className="badge critical">{highEvents} high+</span>}
      </div>

      <div className="tenant-setting">
        <label className="tenant-setting-label" htmlFor={`lvl-${tenant.group}`}>
          Min detection level
        </label>
        <select
          id={`lvl-${tenant.group}`}
          className="tenant-setting-select"
          value={tenant.min_level}
          disabled={update.isPending}
          onChange={(e) => update.mutate({ group: tenant.group, min_level: Number(e.target.value) })}
        >
          {LEVELS.map((l) => (
            <option key={l} value={l}>Level {l}</option>
          ))}
        </select>
        <span className="tenant-setting-hint">
          Only Wazuh alerts ≥ this level are ingested for this tenant.
        </span>
      </div>

      <div className="tenant-card-agents">
        {tenant.agents.map((a) => (
          <span key={a.name} className="tenant-agent-chip">
            {a.name}{a.wazuh_agent_id ? ` · ${a.wazuh_agent_id}` : ""}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Tenants() {
  const { data: tenants = [], isLoading } = useTenants();
  const { data: liveEvents = [] } = useEvents();

  const counts = useMemo(() => {
    const map = new Map<string, { total: number; high: number }>();
    for (const e of liveEvents) {
      if (!e.group) continue;
      const row = map.get(e.group) ?? { total: 0, high: 0 };
      row.total += 1;
      if ((e.wazuh_level ?? 0) >= 10) row.high += 1;
      map.set(e.group, row);
    }
    return map;
  }, [liveEvents]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Tenants</h1>
          <p className="page-sub">Registered companies and the agents reporting into this SOC. Adjust per-tenant detection thresholds.</p>
        </div>
        <span className="page-count">{tenants.length} tenants</span>
      </div>

      {isLoading ? (
        <div className="alert-empty">Loading tenants…</div>
      ) : tenants.length === 0 ? (
        <div className="alert-empty">No tenants registered. Check the backend / database connection.</div>
      ) : (
        <div className="tenant-grid">
          {tenants.map((t) => {
            const c = counts.get(t.group) ?? { total: 0, high: 0 };
            return <TenantCard key={t.group} tenant={t} events={c.total} highEvents={c.high} />;
          })}
        </div>
      )}
    </div>
  );
}
