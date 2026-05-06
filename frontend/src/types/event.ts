export type PipelineStatus = "pending" | "normalized" | "scored" | "explained" | "resolved";
export type ScoringLabel = "benign" | "suspicious" | "malicious" | "critical";

export interface SOCEvent {
  event_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  port: number | null;
  user: string | null;
  event_type: string | null;
  timestamp: string | null;
  raw_log: string | null;
  wazuh_level: number | null;
  rule_id: string | null;
  severity: number | null;
  label: ScoringLabel | null;
  explanation: string | null;
  status: PipelineStatus;
}
