// Small helpers shared by the event views: turning a Wazuh level into a severity
// label and colour, showing times as "5m ago" or a clock, and matching an event
// against a search box.

import type { SOCEvent } from "../types/event";

export type SevClass = "critical" | "high" | "medium" | "low";

// Map a Wazuh rule level (0-15) to a severity class + label.
export function levelInfo(level: number | null): { cls: SevClass; label: string } {
  const l = level ?? 0;
  if (l >= 13) return { cls: "critical", label: "Critical" };
  if (l >= 10) return { cls: "high", label: "High" };
  if (l >= 7) return { cls: "medium", label: "Medium" };
  return { cls: "low", label: "Low" };
}

export const SEV_COLOR: Record<SevClass, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

export function formatAgo(ts: string | null): string {
  if (!ts) return "—";
  const then = Date.parse(ts);
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function formatClock(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// Case-insensitive match across the fields an analyst would search on.
export function matchesSearch(evt: SOCEvent, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const haystack = [
    evt.group,
    evt.agent_name,
    evt.agent_id,
    evt.rule_id,
    evt.rule_description,
    evt.event_type,
    evt.source_ip,
    evt.destination_ip,
    evt.user,
    evt.label,
    ...(evt.mitre_id ?? []),
    ...(evt.mitre_tactic ?? []),
    evt.raw_log,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(q);
}
