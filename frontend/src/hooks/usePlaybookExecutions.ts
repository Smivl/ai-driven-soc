import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

export interface PlaybookExecution {
  id: string;
  playbookId: string;
  clientId: string;
  triggeredBy: string;
  sourceIp: string;
  startedAt: string;
  status: "running" | "completed" | "failed";
  action: string;
}

export function usePlaybookExecutions(limit = 100) {
  return useQuery<PlaybookExecution[]>({
    queryKey: ["playbook-executions"],
    queryFn: async () => {
      const { data } = await api.get<PlaybookExecution[]>(
        `/api/v1/playbook-executions?limit=${limit}`
      );
      return data;
    },
    refetchInterval: 5000,
  });
}
