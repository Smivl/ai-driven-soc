import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Assessments } from "../types/tenant";

// Per-tenant AI agent assessments (keyed by group). Drives the radar.
export function useAssessments() {
  return useQuery<Assessments>({
    queryKey: ["assessments"],
    queryFn: async () => (await api.get<Assessments>("/api/v1/assessments")).data,
    refetchInterval: 5000,
  });
}
