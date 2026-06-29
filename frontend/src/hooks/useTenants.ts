import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Tenant } from "../types/tenant";

// Fetches the list of tenants, refreshing every 10 seconds.
export function useTenants() {
  return useQuery<Tenant[]>({
    queryKey: ["tenants"],
    queryFn: async () => (await api.get<Tenant[]>("/api/v1/tenants")).data,
    refetchInterval: 10000,
  });
}
