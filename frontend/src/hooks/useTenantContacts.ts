import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";

export interface ContactInput {
  name: string;
  role?: string | null;
  email?: string | null;
  phone?: string | null;
}

export function useAddContact(group: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ContactInput) =>
      api.post(`/api/v1/tenants/${encodeURIComponent(group)}/contacts`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}

export function useDeleteContact(group: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (contactId: number) =>
      api.delete(`/api/v1/tenants/${encodeURIComponent(group)}/contacts/${contactId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}
