export interface TenantAgent {
  name: string;
  wazuh_agent_id: string | null;
}

export interface TenantContact {
  id: number;
  name: string;
  role: string | null;
  email: string | null;
  phone: string | null;
}

export interface NotificationRecipient {
  id: number;
  kind: "user" | "email";
  user_id?: number;
  username?: string;
  email: string | null;
}

export type ThreatStatus = "secured" | "at-risk" | "under-attack";

export interface TenantAssessment {
  status: ThreatStatus;
  risk_score: number;
  summary: string;
  ai: boolean; // true = produced by the Ollama agent, false = heuristic fallback
  window: number;
  events: number;
  updated_at: string;
}

export type Assessments = Record<string, TenantAssessment>;

export interface Tenant {
  company: string;
  group: string;
  min_level: number;
  notify_level: number;
  window_size: number;
  description: string | null;
  industry: string | null;
  website: string | null;
  phone: string | null;
  address: string | null;
  agents: TenantAgent[];
  contacts: TenantContact[];
  recipients: NotificationRecipient[];
}
