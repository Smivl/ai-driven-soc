import { useEffect, useState } from "react";
import "../App.css";

type Severity = "critical" | "high" | "medium" | "low";

interface BackendAlert {
  alert_id: string;
  first_seen: string | null;
  last_seen: string | null;
  score: number | null;
  status: string;
  event_count: number;
  source_ips: string[];
  destination_ips: string[];
  users: string[];
  mitre_id: string[];
  mitre_tactic: string[];
  mitre_technique: string[];
  explanation: string | null;
}

interface PlaybookExecution {
  id: string;
  playbookId: string;
  triggeredBy: string;
  sourceIp: string;
  startedAt: string;
  status: string;
  action: string;
}

const API_BASE = "http://localhost:8000/api/v1";

function scoreToSeverity(score: number | null): Severity {
  if (score === null) return "low";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function scoreColor(score: number | null): string {
  if (score === null) return "var(--severity-low)";
  if (score >= 80) return "var(--severity-critical)";
  if (score >= 60) return "var(--severity-high)";
  if (score >= 40) return "var(--severity-medium)";
  return "var(--severity-low)";
}

function formatTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function Navbar({ time }: { time: string }) {
  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <span className="brand-icon">🛡</span>
        AI-Driven SOC
      </div>
      <div className="navbar-status">
        <span className="status-dot" />
        System Operational
      </div>
      <span className="navbar-time">{time}</span>
    </nav>
  );
}

export default function Dashboard() {
  const [time, setTime] = useState(() => new Date().toUTCString().slice(0, 25) + " UTC");
  const [alerts, setAlerts] = useState<BackendAlert[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);

  useEffect(() => {
    const id = setInterval(() => {
      setTime(new Date().toUTCString().slice(0, 25) + " UTC");
    }, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    async function fetchData() {
      try {
        const [alertsRes, execRes] = await Promise.all([
          fetch(`${API_BASE}/alerts?limit=100`),
          fetch(`${API_BASE}/playbook-executions?limit=100`),
        ]);
        if (alertsRes.ok) setAlerts(await alertsRes.json());
        if (execRes.ok) setExecutions(await execRes.json());
      } catch {
        // backend not reachable yet
      }
    }
    fetchData();
    const id = setInterval(fetchData, 30_000);
    return () => clearInterval(id);
  }, []);

  const counts = {
    total: alerts.length,
    critical: alerts.filter((a) => scoreToSeverity(a.score) === "critical").length,
    high: alerts.filter((a) => scoreToSeverity(a.score) === "high").length,
    medium: alerts.filter((a) => scoreToSeverity(a.score) === "medium").length,
    low: alerts.filter((a) => scoreToSeverity(a.score) === "low").length,
  };

  return (
    <div className="layout">
      <Navbar time={time} />
      <div className="page">
        <div className="page-header">
          <h1 className="page-title">Security Operations Dashboard</h1>
          <p className="page-subtitle">Real-time threat monitoring &amp; AI-powered triage</p>
        </div>

        {/* Stat Cards */}
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

        {/* Alerts Table */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Active Alerts</h2>
            <span className="card-badge">{counts.total} alerts</span>
          </div>
          <div className="table-wrap">
            {alerts.length === 0 ? (
              <p style={{ padding: "1rem", color: "var(--text-secondary)" }}>
                No alerts yet — waiting for pipeline data...
              </p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Last Seen</th>
                    <th>MITRE Tactic</th>
                    <th>Source IP</th>
                    <th>User</th>
                    <th>Events</th>
                    <th>Severity</th>
                    <th>AI Score</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => {
                    const severity = scoreToSeverity(alert.score);
                    return (
                      <tr key={alert.alert_id}>
                        <td className="td-mono">{alert.alert_id.slice(0, 8)}</td>
                        <td className="td-mono">{formatTime(alert.last_seen)}</td>
                        <td className="td-event">{alert.mitre_tactic[0] || "—"}</td>
                        <td className="td-ip">{alert.source_ips[0] || "—"}</td>
                        <td style={{ color: "var(--text-secondary)" }}>{alert.users[0] || "—"}</td>
                        <td style={{ color: "var(--text-secondary)" }}>{alert.event_count}</td>
                        <td>
                          <span className={`badge ${severity}`}>{severity}</span>
                        </td>
                        <td>
                          <div className="score-bar">
                            <div className="score-bar-track">
                              <div
                                className="score-bar-fill"
                                style={{
                                  width: `${alert.score ?? 0}%`,
                                  background: scoreColor(alert.score),
                                }}
                              />
                            </div>
                            <span className="score-label">{alert.score ?? 0}</span>
                          </div>
                        </td>
                        <td>
                          <span className={`status ${alert.status === "active" ? "open" : "closed"}`}>
                            {alert.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Playbook Executions Table */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Playbook Executions</h2>
            <span className="card-badge">{executions.length} actions</span>
          </div>
          <div className="table-wrap">
            {executions.length === 0 ? (
              <p style={{ padding: "1rem", color: "var(--text-secondary)" }}>
                No playbook executions yet...
              </p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Playbook</th>
                    <th>Triggered By</th>
                    <th>Source IP</th>
                    <th>Action</th>
                    <th>Time</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {[...executions].reverse().map((ex) => (
                    <tr key={ex.id}>
                      <td>{ex.playbookId}</td>
                      <td className="td-event">{ex.triggeredBy}</td>
                      <td className="td-ip">{ex.sourceIp}</td>
                      <td className="td-mono" style={{ fontSize: "0.78rem" }}>{ex.action}</td>
                      <td className="td-mono">{formatTime(ex.startedAt)}</td>
                      <td>
                        <span className="status closed">{ex.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
