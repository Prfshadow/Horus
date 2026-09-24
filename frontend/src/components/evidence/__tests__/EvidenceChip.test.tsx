import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { EvidenceChip, EvidenceChipList } from "@/components/evidence/EvidenceChip";

function createWrapper() {
  return ({ children }: { children: React.ReactNode }) => (
    <MemoryRouter>{children}</MemoryRouter>
  );
}

describe("EvidenceChip", () => {
  it("renders alert chip with link to alert", () => {
    render(<EvidenceChip id="alert:12" />, { wrapper: createWrapper() });
    const link = screen.getByText("alert:12").closest("a");
    expect(link).toBeInTheDocument();
    expect(link?.getAttribute("href")).toBe("/alerts/12");
  });

  it("renders event chip with link to event", () => {
    render(<EvidenceChip id="event:101" />, { wrapper: createWrapper() });
    const link = screen.getByText("event:101").closest("a");
    expect(link).toBeInTheDocument();
    expect(link?.getAttribute("href")).toBe("/events/101");
  });

  it("renders incident chip with link to incident", () => {
    render(<EvidenceChip id="incident:5" />, { wrapper: createWrapper() });
    const link = screen.getByText("incident:5").closest("a");
    expect(link).toBeInTheDocument();
    expect(link?.getAttribute("href")).toBe("/incidents/5");
  });

  it("renders unknown format as plain text", () => {
    render(<EvidenceChip id="invalid-format" />, { wrapper: createWrapper() });
    const chip = screen.getByText("invalid-format");
    expect(chip).toBeInTheDocument();
    expect(chip.closest("a")).toBeNull();
  });

  it("renders malformed evidence ID as plain text", () => {
    render(<EvidenceChip id="javascript:alert(1)" />, { wrapper: createWrapper() });
    const chip = screen.getByText("javascript:alert(1)");
    expect(chip).toBeInTheDocument();
    expect(chip.closest("a")).toBeNull();
  });
});

describe("EvidenceChipList", () => {
  it("renders multiple evidence chips", () => {
    render(<EvidenceChipList ids={["alert:1", "event:2", "incident:3"]} />, { wrapper: createWrapper() });
    expect(screen.getAllByText("alert:1").length).toBeGreaterThan(0);
    expect(screen.getAllByText("event:2").length).toBeGreaterThan(0);
    expect(screen.getAllByText("incident:3").length).toBeGreaterThan(0);
  });

  it("renders nothing for empty array", () => {
    render(<EvidenceChipList ids={[]} />, { wrapper: createWrapper() });
    expect(screen.queryByText("alert:1")).not.toBeInTheDocument();
  });

  it("renders nothing for null/undefined", () => {
    render(<EvidenceChipList ids={null as unknown as string[]} />, { wrapper: createWrapper() });
    expect(screen.queryByText("alert:1")).not.toBeInTheDocument();
    render(<EvidenceChipList ids={undefined as unknown as string[]} />, { wrapper: createWrapper() });
    expect(screen.queryByText("alert:1")).not.toBeInTheDocument();
  });
});