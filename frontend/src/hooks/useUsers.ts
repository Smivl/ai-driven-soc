import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { SocUser } from "../types/user";

// Admin-only endpoint; the enabled flag lets callers skip the fetch for non-admins.
export function useUsers(enabled = true) {
  return useQuery<SocUser[]>({
    queryKey: ["users"],
    queryFn: async () => (await api.get<SocUser[]>("/api/v1/users")).data,
    enabled,
  });
}
