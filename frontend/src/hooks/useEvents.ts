import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { SOCEvent } from "../types/event";

// Fetches the most recent events from the backend and refreshes every 2 seconds.
export function useEvents(limit = 200) {
  return useQuery<SOCEvent[]>({
    queryKey: ["events"],
    queryFn: async () => {
      const { data } = await api.get<SOCEvent[]>(`/api/v1/events?limit=${limit}`);
      return data;
    },
    refetchInterval: 2000,
  });
}
