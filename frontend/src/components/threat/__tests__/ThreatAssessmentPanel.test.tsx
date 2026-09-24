import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ThreatAssessmentPanel } from "@/components/threat/ThreatAssessmentPanel";
import type { ThreatAssessmentResponse } from "@/api/threatAssessment";

const HIGH: ThreatAssessmentResponse = {
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
  synthetic: false,
  alert_ids: [1, 2, 3, 4, 5],
  incident_ids: [9],
};

const CLEAN: ThreatAssessmentResponse = {
  ...HIGH,
  threat_level: "LOW",
  threat_title: "No Significant Threat Detected",
  explanation: "HORUS analyzed 42 events and found no configured detection conditions.",
  details: [],
  alerts_count: 0,
  incidents_count: 0,
  events_analyzed: 42,
  alert_severities: {},
  incident_severities: {},
  affected_entities: { ips: [], hosts: [], users: [] },
};

function renderPanel(props: Partial<React.ComponentProps<typeof ThreatAssessmentPanel>> = {}) {
  return render(
    <MemoryRouter>
      <ThreatAssessmentPanel
        assessment={HIGH}
        assessing={false}
        error={null}
        onAssess={vi.fn()}
        {...props}
      />
    </MemoryRouter>,
  );
}

describe("ThreatAssessmentPanel", () => {
  it("renders HIGH threat with explanation and counts", () => {
    renderPanel();
    expect(screen.getByText(/HIGH THREAT DETECTED/i)).toBeInTheDocument();
    expect(screen.getByText("Possible Account Compromise")).toBeInTheDocument();
    expect(screen.getByText(/Repeated authentication failures/i)).toBeInTheDocument();
    expect(screen.getByText("View Alerts")).toBeInTheDocument();
    expect(screen.getByText("View Incidents")).toBeInTheDocument();
  });

  it("renders CRITICAL state", () => {
    renderPanel({ assessment: { ...HIGH, threat_level: "CRITICAL" } });
    expect(screen.getByText(/CRITICAL THREAT DETECTED/i)).toBeInTheDocument();
  });

  it("renders no-threat state without false safety claims", () => {
    renderPanel({ assessment: CLEAN });
    expect(screen.getByText(/NO SIGNIFICANT THREAT/i)).toBeInTheDocument();
    expect(screen.getByText(/no configured detection conditions/i)).toBeInTheDocument();
  });

  it("shows synthetic warning for demo data", () => {
    renderPanel({ assessment: { ...HIGH, synthetic: true } });
    expect(screen.getByText(/SYNTHETIC \/ DEMO DATA/i)).toBeInTheDocument();
  });

  it("shows technical evidence on demand", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByText(/Show technical evidence/i));
    expect(screen.getByText(/Alerts by severity/i)).toBeInTheDocument();
  });

  it("calls onAssess when the assess button is clicked", async () => {
    const onAssess = vi.fn();
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ThreatAssessmentPanel assessment={null} assessing={false} error={null} onAssess={onAssess} />
      </MemoryRouter>,
    );
    await user.click(screen.getByRole("button", { name: /Assess recent events/i }));
    expect(onAssess).toHaveBeenCalledTimes(1);
  });

  it("shows analyzing progress while assessing", () => {
    renderPanel({ assessment: null, assessing: true });
    expect(screen.getByText(/Analyzing ingested events/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Assessing/i })).toBeDisabled();
  });

  it("does not claim no threats when assessment fails", () => {
    renderPanel({ assessment: null, error: "boom", eventsReceived: 11 });
    expect(screen.getByText(/Logs stored successfully \(11 events\)/i)).toBeInTheDocument();
    expect(screen.getByText(/could not be completed/i)).toBeInTheDocument();
    expect(screen.queryByText(/NO SIGNIFICANT THREAT/i)).not.toBeInTheDocument();
    expect(screen.getByText(/retry the analysis/i)).toBeInTheDocument();
  });
});
