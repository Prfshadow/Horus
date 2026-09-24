import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { RouterProvider, createMemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { InvestigationPage } from "@/pages/InvestigationPage";

// Mock useInvestigation
vi.mock("@/hooks/useInvestigation", () => ({
  useInvestigation: vi.fn(),
}));

import { useInvestigation } from "@/hooks/useInvestigation";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createMemoryRouter(
    [
      {
        path: "/incidents/:id/investigation",
        element: <InvestigationPage />,
      },
    ],
    { initialEntries: ["/incidents/1/investigation"] },
  );
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

const mockInvestigation = {
  incident: {
    id: 1,
    title: "Brute Force Attack on 10.0.0.5",
    status: "open",
    severity: "HIGH",
    correlation_key: "ip:10.0.0.5",
    context: { strategy: "source_ip", correlation_window_seconds: 3600 },
    first_seen_at: "2026-09-14T10:00:00Z",
    last_seen_at: "2026-09-14T10:30:00Z",
    created_at: "2026-09-14T10:00:00Z",
    updated_at: "2026-09-14T10:30:00Z",
  },
  alerts: [
    {
      id: 1,
      rule_id: 1,
      rule_name: "BruteForceLogin",
      rule_type: "threshold",
      severity: "HIGH",
      status: "detected",
      detected_at: "2026-09-14T10:00:00Z",
      summary: "5 failed logins from 10.0.0.5",
      context: { count: 5, threshold: 5, window_seconds: 60 },
      first_event_id: 1,
      last_event_id: 5,
      evidence_event_ids: [1, 2, 3, 4, 5],
    },
  ],
  events: [
    {
      id: 1,
      timestamp: "2026-09-14T10:00:00Z",
      ingested_at: "2026-09-14T10:00:01Z",
      source: "auth",
      level: "ERROR",
      service: "sshd",
      host: "server-01",
      message: "Failed password for user from 10.0.0.5",
      raw_log: "Sep 14 10:00:00 server-01 sshd[123]: Failed password for user from 10.0.0.5",
      extra_data: { ip: "10.0.0.5", user: "admin" },
    },
  ],
  timeline: [
    { type: "event", id: 1, timestamp: "2026-09-14T10:00:00Z", summary: "Failed password for user from 10.0.0.5" },
    { type: "alert", id: 1, timestamp: "2026-09-14T10:00:00Z", summary: "BruteForceLogin: 5 failed logins from 10.0.0.5" },
  ],
  correlation: {
    strategy: "source_ip",
    correlation_key: "ip:10.0.0.5",
    correlation_window_seconds: 3600,
  },
  summary: {
    alert_count: 1,
    event_count: 1,
    unique_sources: 1,
    unique_hosts: 1,
    unique_services: 1,
    severity_breakdown: { HIGH: 1 },
    time_span_seconds: 1800,
    total_alert_count: 1,
    total_event_count: 1,
    truncated: false,
  },
  entities: {
    ips: ["10.0.0.5"],
    hosts: ["server-01"],
    services: ["sshd"],
    sources: ["auth"],
  },
  detection: [
    {
      alert_id: 1,
      rule_id: 1,
      rule_name: "BruteForceLogin",
      rule_type: "threshold",
      severity: "HIGH",
      summary: "5 failed logins from 10.0.0.5",
      context: { count: 5, threshold: 5, window_seconds: 60 },
    },
  ],
};

const mockEmptyInvestigation = {
  ...mockInvestigation,
  alerts: [],
  events: [],
  timeline: [],
  summary: { ...mockInvestigation.summary, alert_count: 0, event_count: 0 },
  entities: { ips: [], hosts: [], services: [], sources: [] },
  detection: [],
};

const mockTruncatedInvestigation = {
  ...mockInvestigation,
  summary: { ...mockInvestigation.summary, truncated: true, total_alert_count: 150, total_event_count: 600 },
};

describe("InvestigationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useInvestigation as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: mockInvestigation,
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    });
  });

  it("renders investigation header with incident title and metadata", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText("Brute Force Attack on 10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText(/Deterministic Investigation/i)).toBeInTheDocument();
    expect(screen.getAllByText("HIGH").length).toBeGreaterThan(0);
    expect(screen.getAllByText("open").length).toBeGreaterThan(0);
    expect(screen.getAllByText("ip:10.0.0.5").length).toBeGreaterThan(0);
  });

  it("renders investigation summary section", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Investigation Summary/i)).toBeInTheDocument();
  });

  it("renders correlation section", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getAllByText(/Correlation/i).length).toBeGreaterThan(0);
  });

  it("renders detection rules section", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Detection Rules/i)).toBeInTheDocument();
  });

  it("renders timeline section", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Unified Timeline/i)).toBeInTheDocument();
  });

  it("shows loading state", () => {
    (useInvestigation as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: true,
      isError: false,
    });
    render(<InvestigationPage />, { wrapper: createWrapper() });
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("shows error state with retry", () => {
    (useInvestigation as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: true,
      error: new Error("Failed to load"),
      refetch: vi.fn(),
    });
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Unable to load investigation/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retry/i })).toBeInTheDocument();
  });

  it("shows 404 for not found", () => {
    (useInvestigation as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: true,
      error: { status: 404, message: "Not found" },
      refetch: vi.fn(),
    });
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Investigation not found/i)).toBeInTheDocument();
  });

  it("shows empty state for no alerts", () => {
    (useInvestigation as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: mockEmptyInvestigation,
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    });
    render(<InvestigationPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/No alerts in this investigation/i)).toBeInTheDocument();
  });

  it("renders back to incident link", () => {
    render(<InvestigationPage />, { wrapper: createWrapper() });
    const backLink = screen.getByText(/Back to Incident/i);
    expect(backLink).toBeInTheDocument();
    expect(backLink.getAttribute("href")).toBe("/incidents/1");
  });
});