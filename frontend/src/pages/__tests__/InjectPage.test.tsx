import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { InjectPage } from "@/pages/InjectPage";

vi.mock("@/hooks/useIngest", () => ({
  useIngestLogs: vi.fn(),
  ingestAllLines: vi.fn(),
}));

vi.mock("@/hooks/useAdmin", () => ({
  useResetPipeline: vi.fn(),
}));

vi.mock("@/hooks/useThreatAssessment", () => ({
  useThreatAssessment: vi.fn(),
}));

import { useIngestLogs, ingestAllLines } from "@/hooks/useIngest";
import { useResetPipeline } from "@/hooks/useAdmin";
import { useThreatAssessment } from "@/hooks/useThreatAssessment";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const ASSESSMENT = {
  threat_level: "HIGH",
  threat_title: "Possible Account Compromise",
  explanation: "HORUS found strong evidence.",
  details: ["Repeated authentication failures (5 alerts)"],
  alerts_count: 5,
  incidents_count: 1,
  events_analyzed: 30,
  alert_severities: { HIGH: 5 },
  incident_severities: { HIGH: 1 },
  affected_entities: { ips: ["203.0.113.99"], hosts: ["web-01"], users: ["alice"] },
  synthetic: true,
};

describe("InjectPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue({ accepted: 0, failed: 0, results: [] }),
      isPending: false,
      reset: vi.fn(),
    });
    (ingestAllLines as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      accepted: 30,
      failed: 0,
      batches: 1,
      truncated: false,
      eventIds: [201, 202, 203],
    });
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue(ASSESSMENT),
      isPending: false,
    });
    (useResetPipeline as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue({
        events_deleted: 2,
        alerts_deleted: 1,
        incidents_deleted: 1,
        alert_events_deleted: 2,
        incident_alerts_deleted: 1,
      }),
      isPending: false,
      isError: false,
      error: null,
    });
  });

  it("renders inject, threat assessment, lab and danger zone sections", () => {
    render(<InjectPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/INJECT \/\/ HORUS TERMINAL/i)).toBeInTheDocument();
    expect(screen.getByText(/Threat Assessment/i)).toBeInTheDocument();
    expect(screen.getByText(/Synthetic Threat Lab/i)).toBeInTheDocument();
    expect(screen.getByText(/Danger Zone/i)).toBeInTheDocument();
  });

  it("lets the user pick a scenario and generates synthetic telemetry", async () => {
    const user = userEvent.setup();
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("radio", { name: /Privilege Escalation/i }));
    await user.click(screen.getByRole("button", { name: /Generate synthetic scenario and assess/i }));
    await waitFor(() => {
      expect(ingestAllLines).toHaveBeenCalled();
    });
    expect(await screen.findByText(/SYNTHETIC DEMO COMPLETE/i)).toBeInTheDocument();
    expect(await screen.findByText(/SYNTHETIC \/ DEMO DATA/i)).toBeInTheDocument();
  });

  it("scopes the lab assessment to the ingested events", async () => {
    const user = userEvent.setup();
    const assessMutate = vi.fn().mockResolvedValue(ASSESSMENT);
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: assessMutate,
      isPending: false,
    });
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("button", { name: /Generate synthetic scenario and assess/i }));
    await waitFor(() => {
      expect(assessMutate).toHaveBeenCalledWith(
        expect.objectContaining({ synthetic: true, event_ids: [201, 202, 203] }),
      );
    });
  });

  it("shows the HIGH threat result after upload assessment", async () => {
    const user = userEvent.setup();
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("button", { name: /^Assess uploaded events$/i }));
    expect(await screen.findByText(/HIGH THREAT DETECTED/i)).toBeInTheDocument();
    expect(await screen.findByText("Possible Account Compromise")).toBeInTheDocument();
  });

  it("uploading logs automatically triggers a scoped assessment", async () => {
    const user = userEvent.setup();
    const assessMutate = vi.fn().mockResolvedValue(ASSESSMENT);
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: assessMutate,
      isPending: false,
    });
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), "suspicious line one\nsuspicious line two");
    await user.click(screen.getByRole("button", { name: /^Inject logs$/i }));
    await waitFor(() => {
      expect(assessMutate).toHaveBeenCalledWith(
        expect.objectContaining({ synthetic: false, event_ids: [201, 202, 203] }),
      );
    });
    expect(await screen.findByText(/HIGH THREAT DETECTED/i)).toBeInTheDocument();
  });

  it("shows the no-threat result without false safety claims", async () => {
    const user = userEvent.setup();
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue({
        ...ASSESSMENT,
        threat_level: "LOW",
        threat_title: "No Significant Threat Detected",
        explanation: "HORUS analyzed 42 events and found no configured detection conditions.",
        details: [],
        alerts_count: 0,
        incidents_count: 0,
      }),
      isPending: false,
    });
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("button", { name: /^Assess uploaded events$/i }));
    expect(await screen.findByText(/NO SIGNIFICANT THREAT/i)).toBeInTheDocument();
  });

  it("does not claim no threats when assessment fails", async () => {
    const user = userEvent.setup();
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockRejectedValue(new Error("backend exploded")),
      isPending: false,
    });
    render(<InjectPage />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("button", { name: /^Assess uploaded events$/i }));
    expect(await screen.findByText(/could not be completed/i)).toBeInTheDocument();
    expect(screen.queryByText(/NO SIGNIFICANT THREAT/i)).not.toBeInTheDocument();
  });

  it("requires typing RESET before wiping data", async () => {
    const user = userEvent.setup();
    render(<InjectPage />, { wrapper: createWrapper() });
    const wipe = screen.getByRole("button", { name: /Delete all pipeline data/i });
    expect(wipe).toBeDisabled();
    await user.type(screen.getByLabelText(/Type RESET to confirm/i), "RESET");
    expect(screen.getByRole("button", { name: /Delete all pipeline data/i })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: /Delete all pipeline data/i }));
    expect(await screen.findByText(/Cleared 2 events/i)).toBeInTheDocument();
  });
});
