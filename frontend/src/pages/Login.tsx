import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import "../App.css";

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      navigate("/");
    } catch {
      setError("Unable to reach authentication server. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-layout">
      <div className="login-left">
        <div className="login-left-content">
          <p className="login-eyebrow">Security Operations Center</p>
          <h1 className="login-brand">AI-Driven SOC</h1>
          <p className="login-tagline">
            Real-time threat detection and AI-powered triage for modern security teams.
          </p>
        </div>
      </div>

      <div className="login-right">
        <div className="login-form-wrap">
          <h2 className="login-heading">Welcome back</h2>
          <p className="login-subheading">Sign in to access the dashboard.</p>

          <form onSubmit={handleSubmit} className="login-form">
            <div className="login-field">
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </div>
            <div className="login-field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>
            {error && <p className="login-error">{error}</p>}
            <button type="submit" className="login-btn" disabled={loading || !username.trim()}>
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <p className="login-notice">Authorized personnel only. All access is logged.</p>
        </div>
      </div>
    </div>
  );
}
