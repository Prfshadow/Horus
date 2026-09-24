import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("apiFetch", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.stubEnv("VITE_API_BASE_URL", "http://localhost:8000");
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("returns parsed JSON on success in production mode", async () => {
    // Re-import to pick up production env
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "ok", app: "Horus" }),
    } as unknown as Response);

    const data = await apiFetch<{ status: string }>("/api/v1/health");
    expect(data).toEqual({ status: "ok", app: "Horus" });
    expect(global.fetch).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/health",
      expect.objectContaining({ headers: expect.any(Object) }),
    );
  });

  it("uses relative paths when no explicit base URL is set (Vite proxy)", async () => {
    // Re-import without an explicit base URL -> same-origin relative URL
    vi.stubEnv("VITE_API_BASE_URL", "");
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ status: "ok", app: "Horus" }),
    } as unknown as Response);

    const data = await apiFetch<{ status: string }>("/api/v1/health");
    expect(data).toEqual({ status: "ok", app: "Horus" });
    expect(global.fetch).toHaveBeenCalledWith(
      "/api/v1/health",
      expect.objectContaining({ headers: expect.any(Object) }),
    );
  });

  it("throws ApiError on non-2xx", async () => {
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({ detail: "boom" }),
    } as unknown as Response);

    await expect(apiFetch("/api/v1/health")).rejects.toMatchObject({
      status: 500,
      message: "boom",
    });
  });

  it("handles malformed JSON", async () => {
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error("invalid json");
      },
    } as unknown as Response);

    await expect(apiFetch("/api/v1/health")).rejects.toMatchObject({
      message: expect.stringContaining("Invalid JSON"),
    });
  });

  it("handles network error", async () => {
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockRejectedValue(new Error("network down"));

    await expect(apiFetch("/api/v1/health")).rejects.toMatchObject({
      status: 0,
      message: "Network error",
    });
  });

  it("handles 204 No Content", async () => {
    vi.resetModules();
    const { apiFetch } = await import("@/api/client");
    
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => ({}),
    } as unknown as Response);

    const data = await apiFetch("/api/v1/health");
    expect(data).toBeUndefined();
  });
});
