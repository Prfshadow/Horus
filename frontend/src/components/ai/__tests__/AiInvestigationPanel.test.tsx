import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AiInvestigationPanel } from "@/components/ai/AiInvestigationPanel";
import type { AIInvestigateResponse, AIInvestigationAnalysis } from "@/types/api";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const mockAnalysis: AIInvestigationAnalysis = {
  summary: "The incident shows signs of a brute force attack from IP 10.0.0.5 with 5 failed login attempts.",
  observations: [
    {
      statement: "5 failed logins from 10.0.0.5 within 60 seconds",
      type: "fact",
      evidence_ids: ["event:1", "event:2", "event:3", "event:4", "event:5"],
      confidence: null,
    },
    {
      statement: "The pattern suggests automated credential stuffing",
      type: "inference",
      evidence_ids: ["alert:1"],
      confidence: "high",
    },
    {
      statement: "Cannot determine if the source IP belongs to an authorized penetration test",
      type: "uncertainty",
      evidence_ids: [],
      confidence: null,
    },
  ],
  supporting_evidence: ["event:1", "event:2", "alert:1"],
  alternative_explanations: [
    {
      explanation: "Authorized security testing from internal team",
      evidence_ids: ["event:1"],
    },
  ],
  recommended_steps: [
    "Block IP 10.0.0.5 at firewall",
    "Review account lockout policies",
    "Check for successful logins from same IP",
  ],
  limitations: [
    "Limited to 60-second window",
    "No user context available",
  ],
  provenance: {
    provider: "mock",
    model: "mock-model",
    prompt_version: "m6.1-v1",
    schema_version: "1.0",
    incident_id: 1,
    evidence_ids_used: ["event:1", "event:2", "event:3", "event:4", "event:5", "alert:1"],
    truncated: false,
    created_at: "2026-09-14T10:30:00Z",
  },
};

const mockResponse: AIInvestigateResponse = {
  incident_id: 1,
  analysis: mockAnalysis,
  evidence_meta: {
    alerts_used: 1,
    events_used: 5,
    truncated: false,
    total_alerts: 1,
    total_events: 5,
  },
  provenance: mockAnalysis.provenance!,
};

const mockTruncatedResponse: AIInvestigateResponse = {
  ...mockResponse,
  evidence_meta: {
    alerts_used: 100,
    events_used: 500,
    truncated: true,
    total_alerts: 150,
    total_events: 1000,
  },
  provenance: {
    ...mockAnalysis.provenance!,
    truncated: true,
  },
};

const mockErrorResponse: AIInvestigateResponse = {
  ...mockResponse,
  analysis: {
    ...mockAnalysis,
    provenance: {
      ...mockAnalysis.provenance!,
      provider: "deterministic",
      model: "no-llm",
    },
  },
};

describe("AiInvestigationPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders idle state with investigate button", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={null}
        isIdle={true}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Investigation/i)).toBeInTheDocument();
    expect(screen.getByText(/AI-assisted analysis/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Investigate with AI/i })).toBeInTheDocument();
  });

  it("shows loading state", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={true}
        isError={false}
        error={null}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Analyzing the available evidence/i)).toBeInTheDocument();
    const skeletons = document.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("shows error state with retry", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("Failed to load")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Investigation Failed/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Try Again/i })).toBeInTheDocument();
  });

  it("shows 503 provider error message", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("503 AI provider error: unavailable")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/deterministic investigation remains available/i)).toBeInTheDocument();
  });

  it("shows actionable message when no provider is configured", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("AI provider error: unavailable: AI provider disabled")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Not Configured/i)).toBeInTheDocument();
    expect(screen.getByText(/AI_PROVIDER/i)).toBeInTheDocument();
    expect(screen.getByText(/deterministic investigation remains available/i)).toBeInTheDocument();
  });

  it("shows actionable message on authentication failure", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("AI provider error: authentication: Gemini HTTP 401")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Authentication Failed/i)).toBeInTheDocument();
    expect(screen.getByText(/AI_API_KEY/i)).toBeInTheDocument();
  });

  it("shows actionable message when the model is not found", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("AI provider error: unavailable: Gemini model not found (HTTP 404) — check AI_MODEL")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Model Not Found/i)).toBeInTheDocument();
    expect(screen.getByText(/AI_MODEL/i)).toBeInTheDocument();
  });

  it("names timeouts inside provider errors", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("AI provider error: timeout: Groq timeout")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Request Timed Out/i)).toBeInTheDocument();
    expect(screen.getByText(/AI_TIMEOUT/i)).toBeInTheDocument();
  });

  it("names rate limiting inside provider errors", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("AI provider error: rate_limit: Groq HTTP 429")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Rate Limited/i)).toBeInTheDocument();
  });

  it("shows 502 validation error message", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={true}
        error={new Error("502 Invalid AI response")}
        data={null}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Invalid AI Response/i)).toBeInTheDocument();
    expect(screen.getByText(/No AI conclusion was applied/i)).toBeInTheDocument();
  });

  it("renders successful AI analysis with summary", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/AI Investigation/i)).toBeInTheDocument();
    expect(screen.getByText(/AI-assisted/i)).toBeInTheDocument();
    expect(screen.getByText(/brute force attack/i)).toBeInTheDocument();
  });

  it("renders observations", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText("FACT")).toBeInTheDocument();
    expect(screen.getByText("INFERENCE")).toBeInTheDocument();
    expect(screen.getByText("UNCERTAINTY")).toBeInTheDocument();
  });

  it("renders inference observation with confidence", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText("INFERENCE")).toBeInTheDocument();
    expect(screen.getByText("Confidence: high")).toBeInTheDocument();
  });

  it("renders alternative explanations", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Alternative Explanations/i)).toBeInTheDocument();
    expect(screen.getByText("Authorized security testing from internal team")).toBeInTheDocument();
  });

  it("renders recommended steps", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Recommended Investigation Steps/i)).toBeInTheDocument();
    expect(screen.getByText("Block IP 10.0.0.5 at firewall")).toBeInTheDocument();
  });

  it("renders limitations", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Limitations/i)).toBeInTheDocument();
    expect(screen.getByText("Limited to 60-second window")).toBeInTheDocument();
  });

  it("renders provenance with provider and model", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText(/Provenance/i)).toBeInTheDocument();
    expect(screen.getByText("mock")).toBeInTheDocument();
    expect(screen.getByText("mock-model")).toBeInTheDocument();
  });

  it("shows truncation information in provenance", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockTruncatedResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getAllByText(/Truncated/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText(/Alerts used/i)).toBeInTheDocument();
  });

  it("shows insufficient evidence state", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockErrorResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getAllByText(/Insufficient Evidence/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/insufficient evidence available/i)).toBeInTheDocument();
  });

  it("renders re-investigate button", () => {
    render(
      <AiInvestigationPanel
        incidentId={1}
        onInvestigate={vi.fn()}
        isLoading={false}
        isError={false}
        error={null}
        data={mockResponse}
        isIdle={false}
        reset={vi.fn()}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByRole("button", { name: /Re-investigate/i })).toBeInTheDocument();
  });
});