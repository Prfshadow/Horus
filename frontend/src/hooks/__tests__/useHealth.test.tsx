import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as React from "react";
import { useHealth } from "@/hooks/useHealth";
import { healthApi } from "@/api/health";

vi.mock("@/api/health", () => ({
  healthApi: {
    getHealth: vi.fn(),
  },
}));

function createWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useHealth", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows loading initially", () => {
    (healthApi.getHealth as unknown as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    const { result } = renderHook(() => useHealth(), { wrapper: createWrapper() });
    expect(result.current.isLoading).toBe(true);
  });

  it("returns data on success", async () => {
    const mockData = { status: "ok", app: "Horus", env: "dev", database: "connected" };
    (healthApi.getHealth as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(mockData);

    const { result } = renderHook(() => useHealth(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual(mockData);
  });

  it("handles error", async () => {
    const err = new Error("boom") as Error & { status?: number };
    (err as unknown as { status: number }).status = 500;
    (healthApi.getHealth as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(err);

    const { result } = renderHook(() => useHealth(), { wrapper: createWrapper() });

    await waitFor(() => expect(result.current.isError).toBe(true), { timeout: 2000 });
    expect(result.current.error).toBeDefined();
  });
});
