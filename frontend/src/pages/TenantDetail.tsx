// One tenant's detail page. Shows and (for admins) edits the company info, the
// alert and notification thresholds, the AI assessment, and the lists of
// contacts and notification recipients. It is split into the sections below.

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useTenants } from "../hooks/useTenants";
import { useAssessments } from "../hooks/useAssessments";
import { useUpdateTenant } from "../hooks/useUpdateTenant";
import { useUsers } from "../hooks/useUsers";
import { useAddContact, useDeleteContact } from "../hooks/useTenantContacts";
import { useAddRecipient, useDeleteRecipient } from "../hooks/useTenantRecipients";
import type { Tenant } from "../types/tenant";

const LEVELS = Array.from({ length: 16 }, (_, i) => i); // 0..15
const WINDOW_OPTIONS = [5, 10, 20, 30, 50, 75, 100];
const STATUS_LABEL: Record<string, string> = {
  secured: "Secured",
  "at-risk": "At risk",
  "under-attack": "Under attack",
};

function emptyToNull(v: string): string | null {
  const t = v.trim();
  return t === "" ? null : t;
}

// ── Company info ────────────────────────────────────────────────────────────
function InfoSection({ tenant, isAdmin }: { tenant: Tenant; isAdmin: boolean }) {
  const update = useUpdateTenant();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({
    company: "", description: "", industry: "", website: "", phone: "", address: "",
  });

  function startEdit() {
    setForm({
      company: tenant.company,
      description: tenant.description ?? "",
      industry: tenant.industry ?? "",
      website: tenant.website ?? "",
      phone: tenant.phone ?? "",
      address: tenant.address ?? "",
    });
    setEditing(true);
  }

  function save() {
    update.mutate(
      {
        group: tenant.group,
        company: form.company.trim() || tenant.company,
        description: emptyToNull(form.description),
        industry: emptyToNull(form.industry),
        website: emptyToNull(form.website),
        phone: emptyToNull(form.phone),
        address: emptyToNull(form.address),
      },
      { onSuccess: () => setEditing(false) },
    );
  }

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  return (
    <section className="card sharp tenant-section">
      <div className="tenant-section-head">
        <h2 className="tenant-section-title">Company info</h2>
        {isAdmin && !editing && (
          <button className="btn-view" onClick={startEdit}>Edit</button>
        )}
      </div>

      {editing ? (
        <div className="tenant-form">
          <label className="tenant-field">
            <span>Company</span>
            <input className="tenant-input" value={form.company} onChange={set("company")} />
          </label>
          <label className="tenant-field">
            <span>Industry</span>
            <input className="tenant-input" value={form.industry} onChange={set("industry")} placeholder="e.g. Healthcare" />
          </label>
          <label className="tenant-field">
            <span>Website</span>
            <input className="tenant-input" value={form.website} onChange={set("website")} placeholder="https://…" />
          </label>
          <label className="tenant-field">
            <span>Phone</span>
            <input className="tenant-input" value={form.phone} onChange={set("phone")} />
          </label>
          <label className="tenant-field tenant-field-wide">
            <span>Address</span>
            <input className="tenant-input" value={form.address} onChange={set("address")} />
          </label>
          <label className="tenant-field tenant-field-wide">
            <span>Description</span>
            <textarea className="tenant-input" rows={3} value={form.description} onChange={set("description")} />
          </label>
          <div className="tenant-form-actions">
            <button className="btn-primary sharp" onClick={save} disabled={update.isPending}>Save</button>
            <button className="btn-view" onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </div>
      ) : (
        <dl className="tenant-info-grid">
          <div><dt>Industry</dt><dd>{tenant.industry ?? "—"}</dd></div>
          <div><dt>Website</dt><dd>{tenant.website ? <a href={tenant.website} target="_blank" rel="noreferrer">{tenant.website}</a> : "—"}</dd></div>
          <div><dt>Phone</dt><dd>{tenant.phone ?? "—"}</dd></div>
          <div><dt>Address</dt><dd>{tenant.address ?? "—"}</dd></div>
          <div className="tenant-field-wide"><dt>Description</dt><dd>{tenant.description ?? "—"}</dd></div>
        </dl>
      )}
    </section>
  );
}

// ── Contacts ────────────────────────────────────────────────────────────────
function ContactsSection({ tenant, isAdmin }: { tenant: Tenant; isAdmin: boolean }) {
  const add = useAddContact(tenant.group);
  const del = useDeleteContact(tenant.group);
  const [form, setForm] = useState({ name: "", role: "", email: "", phone: "" });

  function submit() {
    if (!form.name.trim()) return;
    add.mutate(
      { name: form.name.trim(), role: emptyToNull(form.role), email: emptyToNull(form.email), phone: emptyToNull(form.phone) },
      { onSuccess: () => setForm({ name: "", role: "", email: "", phone: "" }) },
    );
  }

  return (
    <section className="card sharp tenant-section">
      <div className="tenant-section-head">
        <h2 className="tenant-section-title">Contacts</h2>
        <span className="page-count">{tenant.contacts.length}</span>
      </div>

      {tenant.contacts.length === 0 ? (
        <p className="tenant-empty">No contacts yet.</p>
      ) : (
        <ul className="tenant-list">
          {tenant.contacts.map((c) => (
            <li key={c.id} className="tenant-list-row">
              <div className="tenant-list-main">
                <span className="tenant-list-name">{c.name}</span>
                {c.role && <span className="tenant-list-sub">{c.role}</span>}
              </div>
              <div className="tenant-list-contact">
                {c.email && <a href={`mailto:${c.email}`}>{c.email}</a>}
                {c.phone && <span className="tenant-list-sub">{c.phone}</span>}
              </div>
              {isAdmin && (
                <button className="tenant-remove" title="Remove contact" disabled={del.isPending} onClick={() => del.mutate(c.id)}>×</button>
              )}
            </li>
          ))}
        </ul>
      )}

      {isAdmin && (
        <div className="tenant-addrow">
          <input className="tenant-input" placeholder="Name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
          <input className="tenant-input" placeholder="Role" value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))} />
          <input className="tenant-input" placeholder="Email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} />
          <input className="tenant-input" placeholder="Phone" value={form.phone} onChange={(e) => setForm((f) => ({ ...f, phone: e.target.value }))} />
          <button className="btn-primary sharp" onClick={submit} disabled={add.isPending || !form.name.trim()}>Add</button>
        </div>
      )}
    </section>
  );
}

// ── Settings + notification list ────────────────────────────────────────────
function SettingsSection({ tenant, isAdmin }: { tenant: Tenant; isAdmin: boolean }) {
  const update = useUpdateTenant();
  const addRecipient = useAddRecipient(tenant.group);
  const delRecipient = useDeleteRecipient(tenant.group);
  const { data: users = [] } = useUsers(isAdmin);
  const { data: assessments = {} } = useAssessments();
  const assessment = assessments[tenant.group];
  const [userId, setUserId] = useState("");
  const [email, setEmail] = useState("");

  const linkedUserIds = new Set(tenant.recipients.filter((r) => r.kind === "user").map((r) => r.user_id));
  const availableUsers = users.filter((u) => !linkedUserIds.has(u.id));

  function addUser() {
    if (!userId) return;
    addRecipient.mutate({ user_id: Number(userId) }, { onSuccess: () => setUserId("") });
  }
  function addEmail() {
    const e = email.trim();
    if (!e) return;
    addRecipient.mutate({ email: e }, { onSuccess: () => setEmail("") });
  }

  return (
    <section className="card sharp tenant-section">
      <h2 className="tenant-section-title">AI agent</h2>
      {assessment ? (
        <div className={`tenant-assessment tenant-assessment-${assessment.status}`}>
          <div className="tenant-assessment-head">
            <span className={`badge ${assessment.status === "under-attack" ? "critical" : assessment.status === "at-risk" ? "medium" : ""}`}>
              {STATUS_LABEL[assessment.status] ?? assessment.status}
            </span>
            <span className="tenant-assessment-risk">Risk {assessment.risk_score}/100</span>
            <span className="tenant-assessment-tag">{assessment.ai ? "AI agent" : "heuristic"}</span>
          </div>
          <p className="tenant-assessment-summary">{assessment.summary}</p>
          <span className="tenant-setting-hint">
            Assessed {assessment.events} event(s) over a {assessment.window}-event window.
          </span>
        </div>
      ) : (
        <p className="tenant-empty">No assessment yet — the agent runs once this tenant has events.</p>
      )}

      <h2 className="tenant-section-title tenant-section-spaced">Settings</h2>

      <div className="tenant-levels">
        <div className="tenant-setting">
          <label className="tenant-setting-label">AI window size</label>
          <select
            className="tenant-setting-select"
            value={tenant.window_size}
            disabled={!isAdmin || update.isPending}
            onChange={(e) => update.mutate({ group: tenant.group, window_size: Number(e.target.value) })}
          >
            {WINDOW_OPTIONS.map((w) => <option key={w} value={w}>{w} events</option>)}
          </select>
          <span className="tenant-setting-hint">How many recent events the agent assesses together.</span>
        </div>

        <div className="tenant-setting">
          <label className="tenant-setting-label">Ingestion threshold</label>
          <select
            className="tenant-setting-select"
            value={tenant.min_level}
            disabled={!isAdmin || update.isPending}
            onChange={(e) => update.mutate({ group: tenant.group, min_level: Number(e.target.value) })}
          >
            {LEVELS.map((l) => <option key={l} value={l}>Level {l}</option>)}
          </select>
          <span className="tenant-setting-hint">Only Wazuh alerts ≥ this level are ingested.</span>
        </div>

        <div className="tenant-setting">
          <label className="tenant-setting-label">Notification threshold</label>
          <select
            className="tenant-setting-select"
            value={tenant.notify_level}
            disabled={!isAdmin || update.isPending}
            onChange={(e) => update.mutate({ group: tenant.group, notify_level: Number(e.target.value) })}
          >
            {LEVELS.map((l) => <option key={l} value={l}>Level {l}</option>)}
          </select>
          <span className="tenant-setting-hint">Events ≥ this level alert the notification list below.</span>
        </div>
      </div>

      <h3 className="tenant-subhead">Notification list</h3>
      {tenant.recipients.length === 0 ? (
        <p className="tenant-empty">No recipients. Add SOC users or external emails to be alerted.</p>
      ) : (
        <ul className="tenant-list">
          {tenant.recipients.map((r) => (
            <li key={r.id} className="tenant-list-row">
              <div className="tenant-list-main">
                <span className="tenant-list-name">
                  {r.kind === "user" ? r.username : r.email}
                </span>
                <span className={`badge ${r.kind === "user" ? "" : "medium"}`}>
                  {r.kind === "user" ? "SOC user" : "External"}
                </span>
              </div>
              <div className="tenant-list-contact">
                {r.kind === "user" && <span className="tenant-list-sub">{r.email ?? "no email on account"}</span>}
              </div>
              {isAdmin && (
                <button className="tenant-remove" title="Remove recipient" disabled={delRecipient.isPending} onClick={() => delRecipient.mutate(r.id)}>×</button>
              )}
            </li>
          ))}
        </ul>
      )}

      {isAdmin && (
        <div className="tenant-recipient-add">
          <div className="tenant-addrow">
            <select className="tenant-input" value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">Add a SOC user…</option>
              {availableUsers.map((u) => (
                <option key={u.id} value={u.id}>{u.username}{u.email ? ` (${u.email})` : ""}</option>
              ))}
            </select>
            <button className="btn-primary sharp" onClick={addUser} disabled={!userId || addRecipient.isPending}>Add user</button>
          </div>
          <div className="tenant-addrow">
            <input className="tenant-input" type="email" placeholder="external@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
            <button className="btn-primary sharp" onClick={addEmail} disabled={!email.trim() || addRecipient.isPending}>Add email</button>
          </div>
        </div>
      )}
    </section>
  );
}

export default function TenantDetail() {
  const { group = "" } = useParams();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const { data: tenants = [], isLoading } = useTenants();
  const tenant = tenants.find((t) => t.group === group);

  return (
    <div className="page tenant-detail">
      <div className="detail-topbar">
        <Link to="/tenants" className="btn-back">← Tenants</Link>
      </div>

      {isLoading ? (
        <div className="alert-empty">Loading tenant…</div>
      ) : !tenant ? (
        <div className="alert-empty">Tenant “{group}” not found.</div>
      ) : (
        <>
          <div className="page-head">
            <div>
              <h1 className="page-title">{tenant.company}</h1>
              <p className="page-sub">
                <span className="tenant-group-tag">{tenant.group}</span> · {tenant.agents.length} agents
              </p>
            </div>
            {!isAdmin && <span className="page-count">Read-only</span>}
          </div>

          <div className="tenant-detail-grid">
            <InfoSection tenant={tenant} isAdmin={isAdmin} />
            <ContactsSection tenant={tenant} isAdmin={isAdmin} />
            <SettingsSection tenant={tenant} isAdmin={isAdmin} />
          </div>
        </>
      )}
    </div>
  );
}
