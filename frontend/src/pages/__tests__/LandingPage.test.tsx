import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LandingPage } from "@/pages/LandingPage";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/components/background/MatrixRain", () => ({
  MatrixRain: () => <div data-testid="matrix-rain" />,
}));

vi.mock("@/components/landing/LandingInjectPanel", () => ({
  LandingInjectPanel: () => <div data-testid="landing-inject-panel" />,
}));

function renderLandingPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <LandingPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("LandingPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders HORUS title and LOG INTELLIGENCE subtitle", () => {
    renderLandingPage();
    expect(screen.getByRole("heading", { name: "HORUS" })).toBeInTheDocument();
    expect(screen.getByText("LOG INTELLIGENCE")).toBeInTheDocument();
  });

  it("renders real navigation links to app routes", () => {
    renderLandingPage();
    for (const [label, href] of [
      ["Dashboard", "/dashboard"],
      ["Events", "/events"],
      ["Alerts", "/alerts"],
      ["Incidents", "/incidents"],
    ] as const) {
      const link = screen.getAllByRole("link", { name: label })[0];
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute("href", href);
    }
  });

  it("renders the injection gateway", () => {
    renderLandingPage();
    expect(screen.getByTestId("landing-inject-panel")).toBeInTheDocument();
  });

  it("renders the workflow pipeline steps", () => {
    renderLandingPage();
    const pipeline = screen.getByRole("list", { name: /HORUS workflow/i });
    expect(pipeline).toBeInTheDocument();
    for (const step of ["Inject", "Analyze", "Understand", "Investigate"]) {
      expect(screen.getByText(step)).toBeInTheDocument();
    }
  });

  it("toggles the mobile menu and closes on Escape", async () => {
    renderLandingPage();
    // The toggle is display:none at desktop widths (CSS hides it from the
    // accessibility tree), so query by class; behavior is state-driven.
    const toggle = document.querySelector(".hz-menu-toggle");
    expect(toggle).not.toBeNull();
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(toggle!);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(document.querySelector(".hz-mobile-nav")).toHaveClass("is-open");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(document.querySelector(".hz-mobile-nav")).not.toHaveClass("is-open");
  });

  it("renders the status bar with UTC clock", () => {
    renderLandingPage();
    expect(screen.getByText(/SYS · STANDBY/i)).toBeInTheDocument();
    expect(screen.getByText(/UTC/i)).toBeInTheDocument();
  });
});
