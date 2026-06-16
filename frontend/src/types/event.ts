export type PipelineStatus = "pending" | "normalized" | "scored" | "explained" | "resolved";
export type ScoringLabel = "benign" | "suspicious" | "malicious" | "critical";

export interface SOCEvent {
  event_id: string | null;
  // Tenant attribution — where the event came from
  agent_id: string | null;
  agent_name: string | null;
  group: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  port: number | null;
  user: string | null;
  event_type: string | null;
  timestamp: string | null;
  first_seen: string | null;
  last_seen: string | null;
  raw_log: string | null;
  wazuh_level: number | null;
  rule_id: string | null;
  rule_description: string | null;
  // MITRE ATT&CK mapping (arrays from Wazuh)
  mitre_id: string[] | null;
  mitre_tactic: string[] | null;
  mitre_technique: string[] | null;
  // Raw logs that triggered this event (full_log + previous_output)
  trigger_logs: string[] | null;
  severity: number | null;
  label: ScoringLabel | null;
  explanation: string | null;
  recommended_action: string | null;
  status: PipelineStatus;
}
