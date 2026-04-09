import { useEffect, useState } from "react";
import "../App.css";

type Severity = "critical" | "high" | "medium" | "low";
type Status = "open" | "review" | "closed";

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

const MOCK_ALERTS: Alert[] = [
  { id: "EVT-001", timestamp: "2026-03-11 14:32:07", event_type: "Brute Force", source_ip: "185.220.101.45", user: "admin", severity: "critical", score: 94, status: "open", message: "Multiple failed SSH login attempts detected" },
  { id: "EVT-002", timestamp: "2026-03-11 14:28:51", event_type: "Port Scan", source_ip: "203.0.113.72", user: "—", severity: "high", score: 78, status: "review", message: "SYN scan across 1024 ports in under 2 seconds" },
  { id: "EVT-003", timestamp: "2026-03-11 14:19:33", event_type: "SQL Injection", source_ip: "198.51.100.14", user: "guest", severity: "critical", score: 97, status: "open", message: "SQLi payload detected in login form parameter" },
  { id: "EVT-004", timestamp: "2026-03-11 14:11:02", event_type: "Privilege Escalation", source_ip: "10.0.0.22", user: "jsmith", severity: "high", score: 81, status: "open", message: "User executed sudo with unusual command" },
  { id: "EVT-005", timestamp: "2026-03-11 13:58:47", event_type: "Suspicious DNS", source_ip: "10.0.1.15", user: "—", severity: "medium", score: 55, status: "review", message: "High-frequency DNS queries to newly registered domain" },
  { id: "EVT-006", timestamp: "2026-03-11 13:44:19", event_type: "File Integrity", source_ip: "10.0.0.5", user: "deploy", severity: "medium", score: 49, status: "closed", message: "/etc/passwd modification detected outside change window" },
  { id: "EVT-007", timestamp: "2026-03-11 13:30:05", event_type: "Auth Anomaly", source_ip: "77.88.55.80", user: "mlee", severity: "low", score: 22, status: "closed", message: "Login from new country: RU (usual: US)" },
  { id: "EVT-008", timestamp: "2026-03-11 13:12:44", event_type: "Malware Signature", source_ip: "10.0.2.33", user: "system", severity: "critical", score: 99, status: "open", message: "Known C2 beacon pattern matched in outbound traffic" },
];

function scoreColor(score: number): string {
  if (score >= 80) return "var(--severity-critical)";
  if (score >= 60) return "var(--severity-high)";
  if (score >= 40) return "var(--severity-medium)";
  return "var(--severity-low)";
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

  useEffect(() => {
    const id = setInterval(() => {
      setTime(new Date().toUTCString().slice(0, 25) + " UTC");
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const counts = {
    total: MOCK_ALERTS.length,
    critical: MOCK_ALERTS.filter((a) => a.severity === "critical").length,
    high: MOCK_ALERTS.filter((a) => a.severity === "high").length,
    medium: MOCK_ALERTS.filter((a) => a.severity === "medium").length,
    low: MOCK_ALERTS.filter((a) => a.severity === "low").length,
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
                    <td>
                      <span className={`badge ${alert.severity}`}>{alert.severity}</span>
                    </td>
                    <td>
                      <div className="score-bar">
                        <div className="score-bar-track">
                          <div
                            className="score-bar-fill"
                            style={{ width: `${alert.score}%`, background: scoreColor(alert.score) }}
                          />
                        </div>
                        <span className="score-label">{alert.score}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`status ${alert.status}`}>{alert.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
