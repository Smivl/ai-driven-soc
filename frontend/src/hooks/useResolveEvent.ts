import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";

// Marks a single event resolved, then refetches the events list.
export function useResolveEvent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (eventId: string) =>
      api.post(`/api/v1/events/${encodeURIComponent(eventId)}/resolve`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["events"] }),
  });
}
