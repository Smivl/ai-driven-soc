// The main dashboard: a radar view where every tenant is a dot placed on one of
// three rings by how much danger it is in (secured, at risk, under attack). The
// ring and position come from the tenant's worst active event and its AI
// assessment. Clicking a tenant deep-links into its alerts.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useEvents } from "../hooks/useEvents";
import { useTenants } from "../hooks/useTenants";
import { useAssessments } from "../hooks/useAssessments";
import type { Tenant } from "../types/tenant";
import type { SOCEvent } from "../types/event";

type ThreatLevel = "secured" | "at-risk" | "under-attack";

interface RadarTenant {
  tenant: Tenant;
  status: ThreatLevel;
  maxLevel: number; // worst active Wazuh level seen for this tenant
  activeCount: number;
  risk: number | null; // AI risk score 0-100, when an assessment exists
  ai: boolean; // status came from the AI agent (vs per-event fallback)
  summary: string | null; // AI rationale (shown on hover)
}

type RadarItem =
  | { kind: "tenant"; rt: RadarTenant }
  | { kind: "overflow"; count: number };

// Inner → outer. Inner rings are more severe and sit closer to the centre.
const RING_ORDER: ThreatLevel[] = ["under-attack", "at-risk", "secured"];

// Largest radius (% from centre) a ring's nodes may sit on, by severity.
const RING_MAX_RADIUS: Record<ThreatLevel, number> = {
  "under-attack": 14,
  "at-risk": 31,
  secured: 46,
};

const RING_META: Record<ThreatLevel, { label: string; cls: string }> = {
  "under-attack": { label: "⛊ UNDER ATTACK", cls: "ua" },
  "at-risk": { label: "⚠ AT RISK", cls: "ar" },
  secured: { label: "⛉ SECURED", cls: "sec" },
};

// Hundreds of secured tenants can't all be shown legibly — cap and summarise.
// At-risk / under-attack are not capped: we aim to show every one.
const SECURED_MAX = 16;

// Classify a tenant by the worst active (unresolved) event attributed to it.
function classify(maxLevel: number, activeCount: number): ThreatLevel {
  if (activeCount === 0) return "secured";
  if (maxLevel >= 12) return "under-attack";
  if (maxLevel >= 7) return "at-risk";
  return "secured";
}

function polar(radius: number, deg: number) {
  const rad = (deg * Math.PI) / 180;
  return {
    left: `${50 + radius * Math.cos(rad)}%`,
    top: `${50 + radius * Math.sin(rad)}%`,
  };
}

// Angles (deg) for n nodes: 1 → centred, 2 → side by side across the middle,
// 3+ → regular polygon. The half-step offset keeps a gap at the top (-90°) for
// the ring's label. n=1/2 sit on the horizontal so the cluster stays vertically
// centred (the ring wraps them) instead of bunching at the top.
function anglesFor(n: number): number[] {
  if (n <= 0) return [];
  if (n === 1) return [0];
  if (n === 2) return [180, 0];
  return Array.from({ length: n }, (_, i) => -90 + (360 * (i + 0.5)) / n);
}

function BuildingIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden>
      <path
        d="M3 21h18M5 21V5a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v16M13 21V9a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v12M8 8h2M8 12h2M8 16h2M16 12h0M16 16h0"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { data: tenants = [] } = useTenants();
  const { data: events = [] } = useEvents();
  const { data: assessments = {} } = useAssessments();

  // Fullscreen "TV mode": overlay everything with just the radar, and request
  // native fullscreen for a true kiosk view. Esc / browser exit syncs back.
  const [fullscreen, setFullscreen] = useState(false);
  const toggleFullscreen = useCallback(() => {
    setFullscreen((prev) => {
      const next = !prev;
      try {
        if (next) document.documentElement.requestFullscreen?.();
        else if (document.fullscreenElement) document.exitFullscreen?.();
      } catch {
        /* ignore — fall back to the CSS overlay */
      }
      return next;
    });
  }, []);

  // Hide the app chrome (sidebar + header) while in fullscreen TV mode.
  useEffect(() => {
    document.body.classList.toggle("radar-fullscreen", fullscreen);
    return () => document.body.classList.remove("radar-fullscreen");
  }, [fullscreen]);

  useEffect(() => {
    const onFsChange = () => {
      if (!document.fullscreenElement) setFullscreen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFullscreen(false);
    };
    document.addEventListener("fullscreenchange", onFsChange);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("fullscreenchange", onFsChange);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  // Per-tenant threat status from live, unresolved events.
  const radarTenants = useMemo<RadarTenant[]>(() => {
    const byGroup = new Map<string, { max: number; count: number }>();
    for (const e of events as SOCEvent[]) {
      if (e.status === "resolved" || !e.group) continue;
      const agg = byGroup.get(e.group) ?? { max: 0, count: 0 };
      agg.max = Math.max(agg.max, e.wazuh_level ?? 0);
      agg.count += 1;
      byGroup.set(e.group, agg);
    }
    return tenants.map((tenant) => {
      const agg = byGroup.get(tenant.group) ?? { max: 0, count: 0 };
      const assessment = assessments[tenant.group];
      // The AI agent's holistic verdict drives the ring; fall back to per-event
      // severity only until the first assessment arrives.
      const status = assessment?.status ?? classify(agg.max, agg.count);
      return {
        tenant,
        maxLevel: agg.max,
        activeCount: agg.count,
        status,
        risk: assessment ? assessment.risk_score : null,
        ai: assessment?.ai ?? false,
        summary: assessment?.summary ?? null,
      };
    });
  }, [tenants, events, assessments]);

  const byRing = useMemo(() => {
    const groups: Record<ThreatLevel, RadarTenant[]> = {
      "under-attack": [],
      "at-risk": [],
      secured: [],
    };
    for (const rt of radarTenants) groups[rt.status].push(rt);
    // Worst first within attack/risk; alphabetical for secured.
    groups["under-attack"].sort((a, b) => b.maxLevel - a.maxLevel);
    groups["at-risk"].sort((a, b) => b.maxLevel - a.maxLevel);
    groups.secured.sort((a, b) => a.tenant.company.localeCompare(b.tenant.company));
    return groups;
  }, [radarTenants]);

  const counts = {
    "under-attack": byRing["under-attack"].length,
    "at-risk": byRing["at-risk"].length,
    secured: byRing.secured.length,
  };

  // Geometry for each populated ring: a draw radius (ring circle) plus the
  // positioned items inside it. The innermost present ring is a centred cluster
  // that grows with count; every outer ring's nodes sit in the MIDDLE of their
  // band (between the inner ring and the wall), never hugging the wall.
  const OUTER_WALL = 49;
  const rings = useMemo(() => {
    const present = RING_ORDER.filter((r) => byRing[r].length > 0);
    const k = present.length;
    const out: {
      ring: ThreatLevel;
      drawR: number;
      dense: boolean;
      items: { item: RadarItem; pos: { left: string; top: string } }[];
    }[] = [];

    present.forEach((ring, idx) => {
      // Build the items, capping the secured ring with a "+N" overflow chip.
      let items: RadarItem[];
      if (ring === "secured" && byRing.secured.length > SECURED_MAX) {
        items = [
          ...byRing.secured.slice(0, SECURED_MAX).map((rt) => ({ kind: "tenant", rt } as RadarItem)),
          { kind: "overflow", count: byRing.secured.length - SECURED_MAX },
        ];
      } else {
        items = byRing[ring].map((rt) => ({ kind: "tenant", rt } as RadarItem));
      }

      const n = items.length;
      const maxR = RING_MAX_RADIUS[ring];

      let nodeR: number;
      let drawR: number;
      if (idx === 0) {
        // Innermost present ring: centred cluster that grows with count.
        if (n <= 1) nodeR = 0;
        else if (n === 2) nodeR = Math.min(maxR, 12);
        else nodeR = Math.min(maxR, 7 + n * 1.4);
        nodeR = Math.min(nodeR, 46);
        drawR = Math.min(Math.max(nodeR + 9, 12), OUTER_WALL);
      } else {
        // Outer band: walls spread evenly out to the edge; nodes centred in the band.
        const prevWall = out[idx - 1].drawR;
        drawR = out[0].drawR + ((OUTER_WALL - out[0].drawR) * idx) / (k - 1);
        nodeR = (prevWall + drawR) / 2;
      }

      const angs = anglesFor(n);
      out.push({
        ring,
        drawR,
        dense: n > 10,
        items: items.map((item, i) => ({ item, pos: polar(nodeR, angs[i]) })),
      });
    });
    return out;
  }, [byRing]);

  function openTenant(rt: RadarTenant) {
    // Deep-link into Active Alerts, pre-filtered to this tenant's events.
    navigate(`/alerts?q=${encodeURIComponent(rt.tenant.group)}`);
  }

  return (
    <div className={`page radar-page ${fullscreen ? "fullscreen" : ""}`}>
      <div className="page-head">
        <div>
          <h1 className="page-title">Threat Radar</h1>
          <p className="page-sub">Real-time overview of client security posture.</p>
        </div>
        <div className="radar-head-right">
          <div className="radar-legend">
            {counts["under-attack"] > 0 && (
              <span className="radar-legend-item ua"><i /> Under attack {counts["under-attack"]}</span>
            )}
            {counts["at-risk"] > 0 && (
              <span className="radar-legend-item ar"><i /> At risk {counts["at-risk"]}</span>
            )}
            <span className="radar-legend-item sec"><i /> Secured {counts.secured}</span>
          </div>
          <button
            className="radar-fs-btn"
            onClick={toggleFullscreen}
            title={fullscreen ? "Exit fullscreen (Esc)" : "Fullscreen TV mode"}
          >
            {fullscreen ? (
              <>
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                  <path d="M6 2v4H2M10 2v4h4M6 14v-4H2M10 14v-4h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Exit
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                  <path d="M2 6V2h4M14 6V2h-4M2 10v4h4M14 10v4h-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Fullscreen
              </>
            )}
          </button>
        </div>
      </div>

      <div className="radar-stage">
        <div className="radar-board" key={fullscreen ? "fs" : "win"}>
          {rings.map(({ ring, drawR, dense, items }) => {
            const meta = RING_META[ring];
            const size = `${drawR * 2}%`;
            return (
              <div key={ring}>
                <div
                  className={`radar-ring radar-ring-${ring === "under-attack" ? "attack" : ring === "at-risk" ? "atrisk" : "secured"}`}
                  style={{ width: size, height: size }}
                />
                <span
                  className={`radar-ring-label ${meta.cls}`}
                  style={{ top: `${50 - drawR}%` }}
                >
                  {meta.label}
                </span>
                {items.map(({ item, pos }) =>
                  item.kind === "tenant" ? (
                    <button
                      key={item.rt.tenant.group}
                      className={`radar-node radar-node-${meta.cls} ${dense ? "dense" : ""}`}
                      style={pos}
                      onClick={() => openTenant(item.rt)}
                      title={
                        item.rt.summary
                          ? `${item.rt.tenant.company} — ${item.rt.summary}`
                          : `${item.rt.tenant.company} — view active alerts`
                      }
                    >
                      <span className="radar-node-icon"><BuildingIcon /></span>
                      <span className="radar-node-name">{item.rt.tenant.company}</span>
                      {ring !== "secured" && (
                        <span className="radar-node-level">
                          {item.rt.risk != null ? `Risk ${item.rt.risk}` : `Level ${item.rt.maxLevel}`}
                        </span>
                      )}
                    </button>
                  ) : (
                    <button
                      key="overflow"
                      className={`radar-node radar-node-overflow ${dense ? "dense" : ""}`}
                      style={pos}
                      onClick={() => navigate("/tenants")}
                      title="View all tenants"
                    >
                      <span className="radar-node-icon">+{item.count}</span>
                      <span className="radar-node-name">more secured</span>
                    </button>
                  ),
                )}
              </div>
            );
          })}

          {tenants.length === 0 && <div className="radar-empty">Waiting for tenants…</div>}
        </div>
      </div>
    </div>
  );
}
