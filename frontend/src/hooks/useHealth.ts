import { useQuery } from "@tanstack/react-query";
import { healthApi } from "@/api/health";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => healthApi.getHealth(),
    refetchInterval: 30000,
    retry: 1,
  });
}
