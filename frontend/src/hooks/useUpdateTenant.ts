import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Tenant } from "../types/tenant";

export type TenantPatch = Partial<
  Pick<
    Tenant,
    "company" | "description" | "industry" | "website" | "phone" | "address" | "min_level" | "notify_level"
  >
>;

export function useUpdateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ group, ...fields }: { group: string } & TenantPatch) =>
      api.patch<Tenant>(`/api/v1/tenants/${encodeURIComponent(group)}`, fields),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}
