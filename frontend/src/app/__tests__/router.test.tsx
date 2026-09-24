import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { RouterProvider, createMemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DashboardPage } from "@/pages/DashboardPage";
import { EventsPage } from "@/pages/EventsPage";
import { AlertsPage } from "@/pages/AlertsPage";
import { IncidentsPage } from "@/pages/IncidentsPage";
import { InjectPage } from "@/pages/InjectPage";
import { InvestigationPage } from "@/pages/InvestigationPage";
import { IncidentDetailPage } from "@/pages/IncidentDetailPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { AppShell } from "@/layouts/AppShell";

// Mock health to avoid network
vi.mock("@/hooks/useHealth", () => ({
  useHealth: () => ({ data: { status: "ok", database: "connected" }, isLoading: false, isError: false }),
}));

// Mock useIncident for IncidentDetailPage
vi.mock("@/hooks/useIncidents", () => ({
  useIncidents: vi.fn(),
  useIncident: () => ({
    data: {
      id: 1,
      title: "Test Incident",
      status: "open",
      severity: "HIGH",
      correlation_key: "ip:10.0.0.1",
      context: {},
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      alert_ids: [1],
    },
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
  useRunDetection: () => ({ mutateAsync: vi.fn().mockResolvedValue({ alerts_created: 0, alerts: [] }) }),
  useRunCorrelation: () => ({ mutateAsync: vi.fn().mockResolvedValue({ incidents_created: 0, incidents: [] }) }),
}));

// Mock useInvestigation for InvestigationPage
vi.mock("@/hooks/useInvestigation", () => ({
  useInvestigation: () => ({
    data: {
      incident: {
        id: 1,
        title: "Test Incident",
        status: "open",
        severity: "HIGH",
        correlation_key: "ip:10.0.0.1",
        context: {},
        first_seen_at: new Date().toISOString(),
        last_seen_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      alerts: [],
      events: [],
      timeline: [],
      correlation: { strategy: "source_ip", correlation_key: "ip:10.0.0.1", correlation_window_seconds: 3600 },
      summary: {
        alert_count: 0,
        event_count: 0,
        unique_sources: 0,
        unique_hosts: 0,
        unique_services: 0,
        severity_breakdown: {},
        time_span_seconds: 0,
        total_alert_count: 0,
        total_event_count: 0,
        truncated: false,
      },
      entities: { ips: [], hosts: [], services: [], sources: [] },
      detection: [],
    },
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  }),
}));

function createTestRouter(initialPath: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createMemoryRouter(
    [
      {
        element: <AppShell />,
        children: [
          { path: "/", element: <DashboardPage /> },
          { path: "/dashboard", element: <DashboardPage /> },
          { path: "/events", element: <EventsPage /> },
          { path: "/alerts", element: <AlertsPage /> },
          { path: "/incidents", element: <IncidentsPage /> },
          { path: "/inject", element: <InjectPage /> },
          { path: "/incidents/:id", element: <IncidentDetailPage /> },
          { path: "/incidents/:id/investigation", element: <InvestigationPage /> },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
    { initialEntries: [initialPath] },
  );
  return { router, qc };
}

describe("router", () => {
  it("renders dashboard at /dashboard", async () => {
    const { router, qc } = createTestRouter("/dashboard");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /COMMAND CENTER/i })).toBeInTheDocument();
  });

  it("renders events at /events", async () => {
    const { router, qc } = createTestRouter("/events");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /EVENT EXPLORER/i })).toBeInTheDocument();
  });

  it("renders alerts at /alerts", async () => {
    const { router, qc } = createTestRouter("/alerts");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /ALERT MONITOR/i })).toBeInTheDocument();
  });

  it("renders incidents at /incidents", async () => {
    const { router, qc } = createTestRouter("/incidents");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /Incidents/i })).toBeInTheDocument();
  });

  it("renders inject at /inject", async () => {
    const { router, qc } = createTestRouter("/inject");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByText(/INJECT \/\/ HORUS TERMINAL/i)).toBeInTheDocument();
  });

  it("renders incident detail at /incidents/1", async () => {
    const { router, qc } = createTestRouter("/incidents/1");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /Test Incident/i })).toBeInTheDocument();
  });

  it("renders investigation at /incidents/1/investigation", async () => {
    const { router, qc } = createTestRouter("/incidents/1/investigation");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /Test Incident/i })).toBeInTheDocument();
    // Check for investigation-specific content
    await waitFor(() => {
      expect(screen.getByText(/Deterministic Investigation/i)).toBeInTheDocument();
    });
  });

  it("renders 404 for unknown route", async () => {
    const { router, qc } = createTestRouter("/unknown-xyz");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByText(/Page not found/i)).toBeInTheDocument();
  });

  it("redirects / to /dashboard", async () => {
    const { router, qc } = createTestRouter("/");
    render(
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("heading", { name: /COMMAND CENTER/i })).toBeInTheDocument();
  });
});
