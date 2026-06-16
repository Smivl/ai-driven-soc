export interface TenantAgent {
  name: string;
  wazuh_agent_id: string | null;
}

export interface Tenant {
  company: string;
  group: string;
  min_level: number;
  agents: TenantAgent[];
}
