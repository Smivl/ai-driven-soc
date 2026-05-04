import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import NotificationPanel from "../components/NotificationPanel";
import type { Notification } from "../types/notification";
import "../App.css";

// ── Types ──────────────────────────────────────────────────────────────────────
type Severity = "critical" | "high" | "medium" | "low";
type Status = "open" | "review" | "closed";
type PlaybookCategory = "Detection" | "Response" | "Notification";
type ActiveView = "overview" | "client" | "playbooks";

interface Alert {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip: string;
  user: string;
  severity: Severity;
  score: number;
  status: Status;
  message: string;
}

interface Client {
  id: string;
  name: string;
  environment: string;
}

interface PriorityIssue {
  id: string;
  clientId: string;
  event_type: string;
  source_ip: string;
  severity: "critical" | "high";
  score: number;
  timestamp: string;
  message: string;
}

interface ClientStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface PlaybookExecution {
  id: string;
  playbookId: string;
  clientId: string;
  triggeredBy: string;
  sourceIp: string;
  startedAt: string;
  status: "running" | "completed" | "failed";
  action: string;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: PlaybookCategory;
}

// ── Mock data ──────────────────────────────────────────────────────────────────
const MOCK_CLIENTS: Client[] = [
  { id: "acme",      name: "Acme Corp",   environment: "Production" },
  { id: "techstart", name: "TechStart",   environment: "Production" },
  { id: "megacorp",  name: "MegaCorp",    environment: "Staging"    },
  { id: "globalbnk", name: "GlobalBank",  environment: "Production" },
];

const MOCK_PLAYBOOKS: Playbook[] = [
  { id: "pb1", name: "Auto-Isolate on Ransomware",  description: "Isolate affected hosts when ransomware signatures are detected.", category: "Response"     },
  { id: "pb2", name: "Brute Force Lockout",          description: "Lock accounts after repeated failed authentication attempts.",    category: "Response"     },
  { id: "pb3", name: "Critical Alert Ticket",        description: "Automatically open a ticket for all critical-severity alerts.",   category: "Notification" },
  { id: "pb4", name: "Geo-Anomaly Alert",            description: "Trigger an alert on login from an unusual geographic location.",  category: "Detection"    },
  { id: "pb5", name: "Port Scan Blocklist",          description: "Add port-scanning source IPs to the network blocklist.",          category: "Response"     },
];

const MOCK_CLIENT_STATS: Record<string, ClientStats> = {
  acme:      { total: 24, critical: 5, high: 8,  medium: 7, low: 4 },
  techstart: { total:  7, critical: 0, high: 2,  medium: 3, low: 2 },
  megacorp:  { total: 18, critical: 3, high: 6,  medium: 5, low: 4 },
  globalbnk: { total: 31, critical: 8, high: 12, medium: 7, low: 4 },
};

const MOCK_PRIORITY_ISSUES: PriorityIssue[] = [
  { id: "C-001", clientId: "globalbnk", event_type: "Malware Signature",    source_ip: "10.0.2.33",     severity: "critical", score: 99, timestamp: "14:32", message: "Known C2 beacon pattern matched in outbound traffic" },
  { id: "C-002", clientId: "acme",      event_type: "SQL Injection",        source_ip: "198.51.100.14", severity: "critical", score: 97, timestamp: "14:28", message: "SQLi payload detected in login form parameter" },
  { id: "C-003", clientId: "globalbnk", event_type: "Brute Force",          source_ip: "185.220.101.45",severity: "critical", score: 94, timestamp: "14:19", message: "Multiple failed SSH login attempts" },
  { id: "C-004", clientId: "megacorp",  event_type: "Privilege Escalation", source_ip: "10.0.0.22",     severity: "critical", score: 91, timestamp: "14:11", message: "User executed sudo with unusual command" },
  { id: "C-005", clientId: "acme",      event_type: "Ransomware Detected",  source_ip: "10.4.1.8",      severity: "critical", score: 99, timestamp: "13:58", message: "Ransomware signature matched on host filesystem" },
  { id: "C-006", clientId: "globalbnk", event_type: "Data Exfiltration",    source_ip: "10.1.3.20",     severity: "critical", score: 96, timestamp: "13:44", message: "Large outbound transfer to unknown external host" },
  { id: "H-001", clientId: "megacorp",  event_type: "Port Scan",            source_ip: "203.0.113.72",  severity: "high",     score: 78, timestamp: "14:28", message: "SYN scan across 1024 ports in under 2 seconds" },
  { id: "H-002", clientId: "acme",      event_type: "Privilege Escalation", source_ip: "10.0.0.22",     severity: "high",     score: 81, timestamp: "14:11", message: "User executed sudo with unusual command" },
  { id: "H-003", clientId: "globalbnk", event_type: "Auth Anomaly",         source_ip: "77.88.55.80",   severity: "high",     score: 74, timestamp: "13:58", message: "Multiple accounts accessed from same external IP" },
  { id: "H-004", clientId: "techstart", event_type: "Suspicious DNS",       source_ip: "10.0.1.15",     severity: "high",     score: 71, timestamp: "13:30", message: "High-frequency queries to newly registered domain" },
];

const MOCK_ACTIVE_EXECUTIONS: PlaybookExecution[] = [
  { id: "ex-001", playbookId: "pb1", clientId: "globalbnk", triggeredBy: "Malware Signature",    sourceIp: "10.0.2.33",     startedAt: "14:32:01", status: "running",   action: "Isolating host 10.0.2.33 from the network segment" },
  { id: "ex-002", playbookId: "pb2", clientId: "acme",      triggeredBy: "Brute Force",           sourceIp: "185.220.101.45",startedAt: "14:30:15", status: "running",   action: "Locking account 'admin' after 12 failed attempts" },
  { id: "ex-003", playbookId: "pb3", clientId: "megacorp",  triggeredBy: "Privilege Escalation",  sourceIp: "10.0.0.22",     startedAt: "14:11:10", status: "running",   action: "Opening ticket #4821 in ticketing system" },
  { id: "ex-004", playbookId: "pb5", clientId: "globalbnk", triggeredBy: "Port Scan",             sourceIp: "203.0.113.72",  startedAt: "14:28:55", status: "completed", action: "Added 203.0.113.72 to network blocklist" },
  { id: "ex-005", playbookId: "pb1", clientId: "acme",      triggeredBy: "Ransomware Detected",   sourceIp: "10.4.1.8",      startedAt: "13:59:00", status: "running",   action: "Isolating host 10.4.1.8 from the network segment" },
  { id: "ex-006", playbookId: "pb4", clientId: "globalbnk", triggeredBy: "Auth Anomaly",          sourceIp: "77.88.55.80",   startedAt: "13:30:10", status: "failed",    action: "Geo-lookup failed — external API unreachable" },
];

const INITIAL_NOTIFICATIONS: Notification[] = [
  { id: "n-001", type: "critical", title: "New critical alert",  description: "Malware Signature detected on GlobalBank — host 10.0.2.33",   time: "14:32" },
  { id: "n-002", type: "critical", title: "New critical alert",  description: "SQL Injection attempt on Acme Corp — 198.51.100.14",           time: "14:28" },
  { id: "n-003", type: "critical", title: "New critical alert",  description: "Brute Force detected on GlobalBank — 185.220.101.45",           time: "14:19" },
  { id: "n-004", type: "playbook", title: "Playbook triggered",  description: "Auto-Isolate on Ransomware: isolating 10.4.1.8 (Acme Corp)",   time: "13:59" },
  { id: "n-005", type: "playbook", title: "Playbook completed",  description: "Port Scan Blocklist: 203.0.113.72 added to blocklist",          time: "14:29" },
  { id: "n-006", type: "warning",  title: "Playbook failed",     description: "Geo-Anomaly Alert: external API unreachable (GlobalBank)",      time: "13:30" },
  { id: "n-007", type: "warning",  title: "High severity spike", description: "MegaCorp: 6 high-severity alerts in the last hour",             time: "14:00" },
  { id: "n-008", type: "info",     title: "Session note",        description: "You last signed in yesterday at 18:42",                         time: "09:15" },
];

const DEFAULT_PLAYBOOK_STATES: Record<string, Record<string, boolean>> = {
  acme:      { pb1: true,  pb2: true,  pb3: false, pb4: true,  pb5: false },
  techstart: { pb1: false, pb2: true,  pb3: true,  pb4: true,  pb5: false },
  megacorp:  { pb1: true,  pb2: true,  pb3: true,  pb4: false, pb5: true  },
  globalbnk: { pb1: true,  pb2: true,  pb3: true,  pb4: true,  pb5: true  },
};

const MOCK_ALERTS: Alert[] = [
  { id: "EVT-001", timestamp: "2026-03-11 14:32:07", event_type: "Brute Force",        source_ip: "185.220.101.45", user: "admin",  severity: "critical", score: 94, status: "open",   message: "Multiple failed SSH login attempts detected" },
  { id: "EVT-002", timestamp: "2026-03-11 14:28:51", event_type: "Port Scan",          source_ip: "203.0.113.72",  user: "-",      severity: "high",     score: 78, status: "review", message: "SYN scan across 1024 ports in under 2 seconds" },
  { id: "EVT-003", timestamp: "2026-03-11 14:19:33", event_type: "SQL Injection",      source_ip: "198.51.100.14", user: "guest",  severity: "critical", score: 97, status: "open",   message: "SQLi payload detected in login form parameter" },
  { id: "EVT-004", timestamp: "2026-03-11 14:11:02", event_type: "Privilege Escalation", source_ip: "10.0.0.22",  user: "jsmith", severity: "high",     score: 81, status: "open",   message: "User executed sudo with unusual command" },
  { id: "EVT-005", timestamp: "2026-03-11 13:58:47", event_type: "Suspicious DNS",     source_ip: "10.0.1.15",    user: "-",      severity: "medium",   score: 55, status: "review", message: "High-frequency DNS queries to newly registered domain" },
  { id: "EVT-006", timestamp: "2026-03-11 13:44:19", event_type: "File Integrity",     source_ip: "10.0.0.5",     user: "deploy", severity: "medium",   score: 49, status: "closed", message: "/etc/passwd modification detected outside change window" },
  { id: "EVT-007", timestamp: "2026-03-11 13:30:05", event_type: "Auth Anomaly",       source_ip: "77.88.55.80",  user: "mlee",   severity: "low",      score: 22, status: "closed", message: "Login from new country: RU (usual: US)" },
  { id: "EVT-008", timestamp: "2026-03-11 13:12:44", event_type: "Malware Signature",  source_ip: "10.0.2.33",    user: "system", severity: "critical", score: 99, status: "open",   message: "Known C2 beacon pattern matched in outbound traffic" },
];

// ── Helpers ────────────────────────────────────────────────────────────────────
function scoreColor(score: number): string {
  if (score >= 80) return "var(--severity-critical)";
  if (score >= 60) return "var(--severity-high)";
  if (score >= 40) return "var(--severity-medium)";
  return "var(--severity-low)";
}

const CATEGORY_COLOR: Record<PlaybookCategory, string> = {
  Detection:    "var(--accent-blue)",
  Response:     "var(--severity-high)",
  Notification: "var(--severity-medium)",
};

// ── Chevron ────────────────────────────────────────────────────────────────────
function Chevron({ open }: { open: boolean }) {
  return <span className={`chevron ${open ? "" : "closed"}`} />;
}

// ── Toggle switch ──────────────────────────────────────────────────────────────
function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      className={`toggle ${checked ? "on" : ""}`}
    />
  );
}

// ── Navbar ─────────────────────────────────────────────────────────────────────
function Navbar({ onToggleSidebar, time, notifCount, onToggleNotif }: {
  onToggleSidebar: () => void;
  time: string;
  notifCount: number;
  onToggleNotif: () => void;
}) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <nav className="navbar">
      <div className="navbar-left">
        <button className="sidebar-toggle" onClick={onToggleSidebar} aria-label="Toggle sidebar">
          <span className="hamburger">
            <span /><span /><span />
          </span>
        </button>
        <div className="navbar-brand">AI-Driven SOC</div>
      </div>
      <div className="navbar-status">
        <span className="status-dot" />
        System Operational
      </div>
      <div className="navbar-right">
        <span className="navbar-user">{user?.username}</span>
        <span className="navbar-time">{time}</span>
        <button className="notif-bell-btn" onClick={onToggleNotif} aria-label="Notifications">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 1.5A4.5 4.5 0 0 0 3.5 6v2.5L2 11h12l-1.5-2.5V6A4.5 4.5 0 0 0 8 1.5z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/>
            <path d="M6.5 11a1.5 1.5 0 0 0 3 0" stroke="currentColor" strokeWidth="1.4"/>
          </svg>
          {notifCount > 0 && <span className="notif-badge">{notifCount}</span>}
        </button>
        <button className="logout-btn" onClick={() => { logout(); navigate("/login"); }}>Sign out</button>
      </div>
    </nav>
  );
}

// ── Sidebar ────────────────────────────────────────────────────────────────────
interface SidebarProps {
  open: boolean;
  adminOpen: boolean;
  onToggleAdmin: () => void;
  clientsOpen: boolean;
  onToggleClients: () => void;
  activeView: ActiveView;
  onSetView: (v: ActiveView) => void;
  selectedClientId: string;
  onSelectClient: (id: string) => void;
}

function Sidebar({
  open,
  adminOpen, onToggleAdmin,
  clientsOpen, onToggleClients,
  activeView, onSetView,
  selectedClientId, onSelectClient,
}: SidebarProps) {
  return (
    <aside className={`sidebar ${open ? "" : "sidebar-closed"}`}>
      <div className="sidebar-pinned">
        <button
          className={`sidebar-item ${activeView === "overview" ? "active" : ""}`}
          onClick={() => onSetView("overview")}
        >
          Overview
        </button>
      </div>
      <div className="sidebar-divider" />
      <div className="sidebar-section">
        <button className="sidebar-section-header" onClick={onToggleAdmin}>
          <span>Admin</span>
          <Chevron open={adminOpen} />
        </button>
        <div className={`sidebar-items ${adminOpen ? "" : "sidebar-items-collapsed"}`}>
          <div className="sidebar-items-inner">
            <button
              className={`sidebar-item ${activeView === "playbooks" ? "active" : ""}`}
              onClick={() => onSetView("playbooks")}
            >
              Playbooks
            </button>
          </div>
        </div>
      </div>

      <div className="sidebar-section">
        <button className="sidebar-section-header" onClick={onToggleClients}>
          <span>Clients</span>
          <Chevron open={clientsOpen} />
        </button>
        <div className={`sidebar-items ${clientsOpen ? "" : "sidebar-items-collapsed"}`}>
          <div className="sidebar-items-inner">
            {MOCK_CLIENTS.map((client) => (
              <button
                key={client.id}
                className={`sidebar-item ${activeView === "client" && selectedClientId === client.id ? "active" : ""}`}
                onClick={() => onSelectClient(client.id)}
              >
                <span className="sidebar-item-label">{client.name}</span>
                <span className="sidebar-item-env">{client.environment}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </aside>
  );
}

// ── Active playbooks card ──────────────────────────────────────────────────────
function ActivePlaybooksCard({ clientId }: { clientId?: string }) {
  const executions = clientId
    ? MOCK_ACTIVE_EXECUTIONS.filter((e) => e.clientId === clientId)
    : MOCK_ACTIVE_EXECUTIONS;

  if (executions.length === 0) return null;

  const runningCount = executions.filter((e) => e.status === "running").length;

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">Active Playbooks</h2>
        <span className="card-badge">{runningCount} running</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              {!clientId && <th>Deployment</th>}
              <th>Playbook</th>
              <th>Triggered By</th>
              <th>Source IP</th>
              <th>Action</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {executions.map((exec) => {
              const playbook = MOCK_PLAYBOOKS.find((p) => p.id === exec.playbookId)!;
              const client   = MOCK_CLIENTS.find((c) => c.id === exec.clientId)!;
              return (
                <tr key={exec.id}>
                  <td>
                    <span className={`exec-status exec-${exec.status}`}>
                      <span className="exec-dot" />
                      {exec.status}
                    </span>
                  </td>
                  {!clientId && <td><span className="td-client">{client.name}</span></td>}
                  <td className="td-event">{playbook.name}</td>
                  <td style={{ color: "var(--text-secondary)", fontSize: "0.83rem" }}>{exec.triggeredBy}</td>
                  <td className="td-ip">{exec.sourceIp}</td>
                  <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>{exec.action}</td>
                  <td className="td-mono">{exec.startedAt}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Overview view ──────────────────────────────────────────────────────────────
function OverviewView({ onSelectClient }: { onSelectClient: (id: string) => void }) {
  const sorted = [...MOCK_PRIORITY_ISSUES].sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === "critical" ? -1 : 1;
    return b.score - a.score;
  });

  return (
    <div className="overview-page">
      <div className="overview-body">

        {/* Left — deployment health */}
        <div className="overview-left">
          <p className="overview-panel-label">Deployments</p>
          {MOCK_CLIENTS.map((client) => {
            const stats  = MOCK_CLIENT_STATS[client.id];
            const status = stats.critical > 0 ? "critical" : stats.high > 0 ? "warning" : "ok";
            const label  = status === "critical" ? "Critical" : status === "warning" ? "Warning" : "Healthy";
            return (
              <button key={client.id} className={`deploy-block deploy-block-${status}`} onClick={() => onSelectClient(client.id)}>
                <div className="deploy-block-header">
                  <span className="deploy-block-name">{client.name}</span>
                  <span className={`deploy-block-status deploy-status-${status}`}>{label}</span>
                </div>
                <span className="deploy-block-env">{client.environment}</span>
                <div className="deploy-block-counts">
                  <span style={{ color: "var(--severity-critical)" }}>{stats.critical} critical</span>
                  <span style={{ color: "var(--severity-high)" }}>{stats.high} high</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Right — threat feed */}
        <div className="overview-right">
          <p className="overview-panel-label">Active Threats</p>
          {sorted.map((issue) => {
            const client = MOCK_CLIENTS.find((c) => c.id === issue.clientId)!;
            return (
              <div key={issue.id} className={`noc-row noc-${issue.severity}`} onClick={() => onSelectClient(issue.clientId)}>
                <span className={`badge ${issue.severity}`}>{issue.severity}</span>
                <div className="noc-main">
                  <span className="noc-event">{issue.event_type}</span>
                  <span className="noc-detail">{issue.source_ip} &mdash; {issue.message}</span>
                </div>
                <div className="noc-meta">
                  <span className="noc-client">{client.name}</span>
                  <span className="noc-time">{issue.timestamp}</span>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
}

// ── Playbooks view ─────────────────────────────────────────────────────────────
function PlaybooksView({
  playbookStates,
  onToggle,
}: {
  playbookStates: Record<string, Record<string, boolean>>;
  onToggle: (clientId: string, playbookId: string) => void;
}) {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Playbooks</h1>
          <p className="page-subtitle">Manage automated response playbooks across all deployments.</p>
        </div>
        <button className="btn-primary" onClick={() => {}}>+ Create Playbook</button>
      </div>
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Playbook Matrix</h2>
          <span className="card-badge">{MOCK_PLAYBOOKS.length} playbooks</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th style={{ minWidth: 220 }}>Playbook</th>
                <th>Category</th>
                {MOCK_CLIENTS.map((c) => (
                  <th key={c.id} style={{ textAlign: "center" }}>{c.name}</th>
                ))}
                <th />
              </tr>
            </thead>
            <tbody>
              {MOCK_PLAYBOOKS.map((pb) => (
                <tr key={pb.id}>
                  <td>
                    <div className="pb-name">{pb.name}</div>
                    <div className="pb-desc">{pb.description}</div>
                  </td>
                  <td>
                    <span className="pb-category" style={{ color: CATEGORY_COLOR[pb.category] }}>
                      {pb.category}
                    </span>
                  </td>
                  {MOCK_CLIENTS.map((c) => (
                    <td key={c.id} style={{ textAlign: "center" }}>
                      <Toggle
                        checked={playbookStates[c.id]?.[pb.id] ?? false}
                        onChange={() => onToggle(c.id, pb.id)}
                      />
                    </td>
                  ))}
                  <td>
                    <button className="btn-edit" onClick={() => {}}>Edit</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Client view ────────────────────────────────────────────────────────────────
function ClientView({ clientId }: { clientId: string }) {
  const client = MOCK_CLIENTS.find((c) => c.id === clientId)!;
  const counts = {
    total:    MOCK_ALERTS.length,
    critical: MOCK_ALERTS.filter((a) => a.severity === "critical").length,
    high:     MOCK_ALERTS.filter((a) => a.severity === "high").length,
    medium:   MOCK_ALERTS.filter((a) => a.severity === "medium").length,
    low:      MOCK_ALERTS.filter((a) => a.severity === "low").length,
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">{client.name}</h1>
        <p className="page-subtitle">{client.environment} — Real-time threat monitoring &amp; AI-powered triage</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Total Alerts</span>
          <span className="stat-value total">{counts.total}</span>
          <span className="stat-trend">Last 24 hours</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Critical</span>
          <span className="stat-value critical">{counts.critical}</span>
          <span className="stat-trend">Immediate action required</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">High</span>
          <span className="stat-value high">{counts.high}</span>
          <span className="stat-trend">Investigate soon</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Medium</span>
          <span className="stat-value medium">{counts.medium}</span>
          <span className="stat-trend">Monitor closely</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Low</span>
          <span className="stat-value low">{counts.low}</span>
          <span className="stat-trend">Low risk</span>
        </div>
      </div>

      <ActivePlaybooksCard clientId={clientId} />

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Recent Alerts</h2>
          <span className="card-badge">{counts.total} events</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>User</th>
                <th>Severity</th>
                <th>AI Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_ALERTS.map((alert) => (
                <tr key={alert.id}>
                  <td className="td-mono">{alert.id}</td>
                  <td className="td-mono">{alert.timestamp}</td>
                  <td className="td-event">{alert.event_type}</td>
                  <td className="td-ip">{alert.source_ip}</td>
                  <td style={{ color: "var(--text-secondary)" }}>{alert.user}</td>
                  <td><span className={`badge ${alert.severity}`}>{alert.severity}</span></td>
                  <td>
                    <div className="score-bar">
                      <div className="score-bar-track">
                        <div className="score-bar-fill" style={{ width: `${alert.score}%`, background: scoreColor(alert.score) }} />
                      </div>
                      <span className="score-label">{alert.score}</span>
                    </div>
                  </td>
                  <td><span className={`status ${alert.status}`}>{alert.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [time, setTime] = useState(() => new Date().toUTCString().slice(0, 25) + " UTC");
  const [sidebarOpen, setSidebarOpen]   = useState(true);
  const [adminOpen, setAdminOpen]       = useState(true);
  const [clientsOpen, setClientsOpen]   = useState(true);
  const [activeView, setActiveView]     = useState<ActiveView>("overview");
  const [selectedClientId, setSelectedClientId] = useState(MOCK_CLIENTS[0].id);
  const [playbookStates, setPlaybookStates]     = useState(DEFAULT_PLAYBOOK_STATES);
  const [notifications, setNotifications]       = useState(INITIAL_NOTIFICATIONS);
  const [notifOpen, setNotifOpen]               = useState(false);

  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toUTCString().slice(0, 25) + " UTC"), 1000);
    return () => clearInterval(id);
  }, []);

  function handleTogglePlaybook(clientId: string, playbookId: string) {
    setPlaybookStates((prev) => ({
      ...prev,
      [clientId]: { ...prev[clientId], [playbookId]: !prev[clientId][playbookId] },
    }));
  }

  function handleSelectClient(clientId: string) {
    setSelectedClientId(clientId);
    setActiveView("client");
  }

  return (
    <div className="layout">
      <Navbar
        onToggleSidebar={() => setSidebarOpen((o) => !o)}
        time={time}
        notifCount={notifications.length}
        onToggleNotif={() => setNotifOpen((o) => !o)}
      />
      <div className="dashboard-body">
        <Sidebar
          open={sidebarOpen}
          adminOpen={adminOpen}       onToggleAdmin={() => setAdminOpen((o) => !o)}
          clientsOpen={clientsOpen}   onToggleClients={() => setClientsOpen((o) => !o)}
          activeView={activeView}     onSetView={setActiveView}
          selectedClientId={selectedClientId} onSelectClient={handleSelectClient}
        />
        <main className="main-content">
          {activeView === "overview"  && <OverviewView  key="overview"         onSelectClient={handleSelectClient} />}
          {activeView === "playbooks" && <PlaybooksView key="playbooks"        playbookStates={playbookStates} onToggle={handleTogglePlaybook} />}
          {activeView === "client"    && <ClientView    key={selectedClientId} clientId={selectedClientId} />}
        </main>
      </div>
      <NotificationPanel
        open={notifOpen}
        notifications={notifications}
        onDismiss={(id) => setNotifications((n) => n.filter((x) => x.id !== id))}
        onClearAll={() => setNotifications([])}
        onClose={() => setNotifOpen(false)}
      />
    </div>
  );
}
