import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DashboardPage } from "@/pages/DashboardPage";

// Mock hooks
vi.mock("@/hooks/useHealth", () => ({
  useHealth: vi.fn(() => ({ data: { status: "ok", database: "connected", app: "Horus", env: "dev" }, isLoading: false, isError: false })),
}));
vi.mock("@/hooks/useStats", () => ({
  useStats: vi.fn(),
}));
vi.mock("@/hooks/useRecentAlerts", () => ({
  useRecentAlerts: vi.fn(),
}));
vi.mock("@/hooks/useRecentIncidents", () => ({
  useRecentIncidents: vi.fn(),
}));
vi.mock("@/hooks/useRecentEvents", () => ({
  useRecentEvents: vi.fn(),
}));

import { useStats } from "@/hooks/useStats";
import { useRecentAlerts } from "@/hooks/useRecentAlerts";
import { useRecentIncidents } from "@/hooks/useRecentIncidents";
import { useRecentEvents } from "@/hooks/useRecentEvents";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const mockStats = {
  events: { total: 42 },
  alerts: { total: 10, active: 5, by_severity: { HIGH: 3, MEDIUM: 2 }, by_status: { detected: 5 } },
  incidents: { total: 4, open: 2, investigating: 1, resolved: 1, by_severity: { HIGH: 2 } },
  generated_at: new Date().toISOString(),
};

const mockAlerts = [
  { id: 1, rule_name: "BruteForceLogin", severity: "HIGH", status: "detected", detected_at: new Date().toISOString(), summary: "test" },
  { id: 2, rule_name: "ErrorSpike", severity: "MEDIUM", status: "acknowledged", detected_at: new Date().toISOString(), summary: "test2" },
];

const mockIncidents = {
  items: [
    { id: 1, title: "Incident 1", status: "open", severity: "HIGH", correlation_key: "ip:1.1.1.1", first_seen_at: new Date().toISOString(), last_seen_at: new Date().toISOString(), alert_ids: [1] },
  ],
  page: 1,
  page_size: 5,
  total: 1,
  total_pages: 1,
};

const mockEvents = [
  { id: 1, timestamp: new Date().toISOString(), source: "auth", level: "ERROR", message: "fail", raw_log: "raw", extra_data: null, ingested_at: new Date().toISOString(), service: null, host: null },
];

const mockPaginatedEvents = {
  items: mockEvents,
  page: 1,
  page_size: 5,
  total: 1,
  total_pages: 1,
};

const mockEmptyPaginatedEvents = {
  items: [],
  page: 1,
  page_size: 5,
  total: 0,
  total_pages: 1,
};

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useStats as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: mockStats, isLoading: false, isError: false, refetch: vi.fn() });
    (useRecentAlerts as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: mockAlerts, isLoading: false, isError: false, refetch: vi.fn() });
    (useRecentIncidents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: mockIncidents, isLoading: false, isError: false, refetch: vi.fn() });
    (useRecentEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: mockPaginatedEvents, isLoading: false, isError: false, refetch: vi.fn() });
  });

  it("renders command center header", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByRole("heading", { name: /COMMAND CENTER/i })).toBeInTheDocument();
    expect(screen.getAllByText(/^Command center$/i)).toHaveLength(2);
  });

  it("shows loading skeletons", () => {
    (useStats as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: true, isError: false });
    (useRecentAlerts as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: true, isError: false });
    (useRecentIncidents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: true, isError: false });
    (useRecentEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: true, isError: false });
    render(<DashboardPage />, { wrapper: createWrapper() });
    // Should have skeletons (at least one)
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("shows overview stats with real data", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Events")).toBeInTheDocument();
    expect(screen.getAllByText("42").length).toBeGreaterThan(0);
    expect(screen.getByText("Active Alerts")).toBeInTheDocument();
    expect(screen.getAllByText("5").length).toBeGreaterThan(0);
    expect(screen.getByText("Open Incidents")).toBeInTheDocument();
    expect(screen.getAllByText("2").length).toBeGreaterThan(0);
  });

  it("shows empty states", () => {
    (useRecentAlerts as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: [], isLoading: false, isError: false });
    (useRecentIncidents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: { items: [], page: 1, page_size: 5, total: 0, total_pages: 1 }, isLoading: false, isError: false });
    (useRecentEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ data: mockEmptyPaginatedEvents, isLoading: false, isError: false });
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/No alerts yet/i)).toBeInTheDocument();
    expect(screen.getByText(/No incidents yet/i)).toBeInTheDocument();
    expect(screen.getByText(/No events yet/i)).toBeInTheDocument();
  });

  it("handles partial failure", () => {
    (useRecentAlerts as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: false, isError: true, refetch: vi.fn() });
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Unable to load alerts/i)).toBeInTheDocument();
    // Other sections still render
    expect(screen.getByText("Events")).toBeInTheDocument();
  });

  it("shows severity overview", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Alert Severity")).toBeInTheDocument();
    expect(screen.getByText("Incident Severity")).toBeInTheDocument();
    expect(screen.getAllByText("HIGH").length).toBeGreaterThan(0);
  });

  it("renders recent alerts with navigation", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText("BruteForceLogin")).toBeInTheDocument();
    const link = screen.getByText("BruteForceLogin").closest("a");
    expect(link?.getAttribute("href")).toMatch(/\/alerts\/\d+/);
  });

  it("renders recent incidents with navigation", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Incident 1")).toBeInTheDocument();
  });

  it("shows last updated and refresh", async () => {
    const user = userEvent.setup();
    render(<DashboardPage />, { wrapper: createWrapper() });
    const btn = screen.getByRole("button", { name: /Refresh/i });
    expect(btn).toBeInTheDocument();
    await user.click(btn);
    // After refresh, still shows header
    expect(screen.getByRole("heading", { name: /COMMAND CENTER/i })).toBeInTheDocument();
  });

  it("shows system status", () => {
    render(<DashboardPage />, { wrapper: createWrapper() });
    expect(screen.getByText("System Status")).toBeInTheDocument();
    expect(screen.getByText("HORUS Core")).toBeInTheDocument();
  });
});
