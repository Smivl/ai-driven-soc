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

export interface Tenant {
  company: string;
  group: string;
  min_level: number;
  notify_level: number;
  description: string | null;
  industry: string | null;
  website: string | null;
  phone: string | null;
  address: string | null;
  agents: TenantAgent[];
  contacts: TenantContact[];
  recipients: NotificationRecipient[];
}
