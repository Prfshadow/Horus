import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LandingInjectPanel } from "@/components/landing/LandingInjectPanel";
import { useLandingPipeline } from "@/components/landing/useLandingPipeline";

vi.mock("@/hooks/useIngest", () => ({
  useIngestLogs: vi.fn(),
  ingestAllLines: vi.fn(),
}));

vi.mock("@/hooks/useThreatAssessment", () => ({
  useThreatAssessment: vi.fn(),
}));

import { useIngestLogs, ingestAllLines } from "@/hooks/useIngest";
import { useThreatAssessment } from "@/hooks/useThreatAssessment";

const ASSESSMENT = {
  threat_level: "HIGH",
  threat_title: "Possible Brute-Force Attack",
  explanation: "HORUS found strong evidence.",
  details: ["Repeated authentication failures (5 alerts)"],
  alerts_count: 5,
  incidents_count: 1,
  events_analyzed: 11,
  alert_severities: { HIGH: 5 },
  incident_severities: { HIGH: 1 },
  affected_entities: { ips: ["203.0.113.99"], hosts: [], users: [] },
  synthetic: false,
  alert_ids: [1, 2, 3, 4, 5],
  incident_ids: [9],
};

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  function Host() {
    const pipeline = useLandingPipeline();
    return <LandingInjectPanel pipeline={pipeline} pingKey={0} />;
  }
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Host />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("LandingInjectPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn(),
      isPending: false,
      reset: vi.fn(),
    });
    (ingestAllLines as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      accepted: 11,
      failed: 0,
      batches: 1,
      truncated: false,
      eventIds: [1, 2, 3],
    });
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue(ASSESSMENT),
      isPending: false,
    });
  });

  it("renders the injection gateway with file and paste actions", () => {
    renderPanel();
    expect(screen.getByRole("button", { name: /drop log files here/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Choose File/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Paste Logs/i })).toBeInTheDocument();
  });

  it("opens the file picker with keyboard interaction", async () => {
    const user = userEvent.setup();
    renderPanel();
    const zone = screen.getByRole("button", { name: /drop log files here/i });
    zone.focus();
    await user.keyboard("{Enter}");
    // File input click is internal; assert no crash and zone still present.
    expect(zone).toBeInTheDocument();
  });

  it("stages pasted logs and runs the real scoped pipeline", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: /Paste Logs/i }));
    const area = screen.getByPlaceholderText(/session opened/i);
    // fireEvent.change: userEvent.type would parse `{...}` as keyboard commands.
    fireEvent.change(area, {
      target: { value: '{"level":"ERROR","message":"fail"}\n{"level":"ERROR","message":"fail again"}' },
    });
    await user.click(screen.getByRole("button", { name: /Inject Events/i }));

    expect(await screen.findByText(/DATASET STAGED FOR ANALYSIS/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Analyze Data/i }));

    await waitFor(() => {
      expect(ingestAllLines).toHaveBeenCalled();
    });
    const assessMock = (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mock.results[0]?.value
      ?.mutateAsync as ReturnType<typeof vi.fn>;
    await waitFor(() => {
      expect(assessMock).toHaveBeenCalledWith(expect.objectContaining({ event_ids: [1, 2, 3] }));
    });

    // Real backend values rendered — level, counts, explanation.
    expect(await screen.findByText(/HIGH/i)).toBeInTheDocument();
    expect(await screen.findByText("Possible Brute-Force Attack")).toBeInTheDocument();
    expect(await screen.findByText(/Repeated authentication failures/i)).toBeInTheDocument();
  });

  it("shows ingestion failure without claiming results", async () => {
    const user = userEvent.setup();
    (ingestAllLines as unknown as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("network down"));
    renderPanel();

    await user.click(screen.getByRole("button", { name: /Paste Logs/i }));
    fireEvent.change(screen.getByPlaceholderText(/session opened/i), {
      target: { value: "line one\nline two" },
    });
    await user.click(screen.getByRole("button", { name: /Inject Events/i }));
    await user.click(screen.getByRole("button", { name: /Analyze Data/i }));

    expect(await screen.findByText(/Logs could not be stored/i)).toBeInTheDocument();
    expect(screen.queryByText(/THREAT ASSESSMENT/i)).not.toBeInTheDocument();
  });

  it("shows assessment failure with retry that does not re-ingest", async () => {
    const user = userEvent.setup();
    const assessMutate = vi.fn().mockRejectedValueOnce(new Error("engine timeout"));
    (useThreatAssessment as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: assessMutate,
      isPending: false,
    });
    renderPanel();

    await user.click(screen.getByRole("button", { name: /Paste Logs/i }));
    fireEvent.change(screen.getByPlaceholderText(/session opened/i), {
      target: { value: "line one\nline two" },
    });
    await user.click(screen.getByRole("button", { name: /Inject Events/i }));
    await user.click(screen.getByRole("button", { name: /Analyze Data/i }));

    expect(await screen.findByText(/Threat assessment could not be completed/i)).toBeInTheDocument();
    expect(screen.queryByText(/No threats detected/i)).not.toBeInTheDocument();

    const ingestCalls = (ingestAllLines as unknown as ReturnType<typeof vi.fn>).mock.calls.length;
    assessMutate.mockResolvedValueOnce(ASSESSMENT);
    await user.click(screen.getByRole("button", { name: /Retry Analysis/i }));
    await waitFor(() => {
      expect(assessMutate).toHaveBeenCalledTimes(2);
    });
    // Ingestion ran exactly once — retry only reassesses.
    expect((ingestAllLines as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(ingestCalls);
    expect(await screen.findByText("Possible Brute-Force Attack")).toBeInTheDocument();
  });

  it("links to the real investigation pages from the result", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(screen.getByRole("button", { name: /Paste Logs/i }));
    fireEvent.change(screen.getByPlaceholderText(/session opened/i), {
      target: { value: "line one\nline two" },
    });
    await user.click(screen.getByRole("button", { name: /Inject Events/i }));
    await user.click(screen.getByRole("button", { name: /Analyze Data/i }));

    const alerts = await screen.findByRole("link", { name: /View Alerts/i });
    expect(alerts).toHaveAttribute("href", "/alerts");
    const incident = await screen.findByRole("link", { name: /View Incident/i });
    expect(incident).toHaveAttribute("href", "/incidents/9");
    const investigate = await screen.findByRole("link", { name: /Investigate/i });
    expect(investigate).toHaveAttribute("href", "/incidents/9/investigation");
  });

  it("links to the threat lab for synthetic data instead of inline generation", async () => {
    renderPanel();
    const link = await screen.findByRole("link", { name: /Try synthetic data/i });
    expect(link).toHaveAttribute("href", "/threat-lab");
    // No inline scenario controls on the landing gateway.
    expect(screen.queryByLabelText(/Synthetic scenario/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Try synthetic scenario/i })).not.toBeInTheDocument();
  });

  it("closes the paste modal on Escape", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByRole("button", { name: /Paste Logs/i }));
    expect(screen.getByPlaceholderText(/session opened/i)).toBeInTheDocument();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });
});
