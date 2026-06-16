import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Tenant } from "../types/tenant";

export function useUpdateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ group, min_level }: { group: string; min_level: number }) =>
      api.patch<Tenant>(`/api/v1/tenants/${encodeURIComponent(group)}`, { min_level }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}
