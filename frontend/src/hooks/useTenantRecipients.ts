import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";

export interface RecipientInput {
  user_id?: number;
  email?: string;
}

export function useAddRecipient(group: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RecipientInput) =>
      api.post(`/api/v1/tenants/${encodeURIComponent(group)}/recipients`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}

export function useDeleteRecipient(group: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (recipientId: number) =>
      api.delete(`/api/v1/tenants/${encodeURIComponent(group)}/recipients/${recipientId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}
