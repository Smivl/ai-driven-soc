// The tenants list: one card per tenant showing its agents, event counts, and
// alert thresholds. Each card links to that tenant's detail page.

import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useTenants } from "../hooks/useTenants";
import { useEvents } from "../hooks/useEvents";
import type { Tenant } from "../types/tenant";

function TenantCard({ tenant, events, highEvents }: { tenant: Tenant; events: number; highEvents: number }) {
  return (
    <Link to={`/tenants/${encodeURIComponent(tenant.group)}`} className="card sharp tenant-card tenant-card-link">
      <div className="tenant-card-head">
        <span className="tenant-card-name">{tenant.company}</span>
        <span className="tenant-group-tag">{tenant.group}</span>
      </div>

      {tenant.industry && <div className="tenant-card-industry">{tenant.industry}</div>}

      <div className="tenant-card-stats">
        <span><strong>{tenant.agents.length}</strong> agents</span>
        <span><strong>{events}</strong> events</span>
        <span><strong>{tenant.contacts.length}</strong> contacts</span>
        {highEvents > 0 && <span className="badge critical">{highEvents} high+</span>}
      </div>

      <div className="tenant-card-meta">
        <span className="tenant-card-chip">Ingest ≥ L{tenant.min_level}</span>
        <span className="tenant-card-chip">Notify ≥ L{tenant.notify_level}</span>
        <span className="tenant-card-chip">
          {tenant.recipients.length} recipient{tenant.recipients.length === 1 ? "" : "s"}
        </span>
      </div>
    </Link>
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
          <p className="page-sub">Registered companies and the agents reporting into this SOC. Select a tenant to manage its details, contacts, and notifications.</p>
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
