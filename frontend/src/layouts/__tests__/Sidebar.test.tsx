import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "@/layouts/Sidebar";

describe("Sidebar", () => {
  it("renders all navigation links when mobile open", () => {
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={true} onMobileClose={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.getByLabelText("Dashboard")).toBeInTheDocument();
    expect(screen.getByLabelText("Events")).toBeInTheDocument();
    expect(screen.getByLabelText("Alerts")).toBeInTheDocument();
    expect(screen.getByLabelText("Incidents")).toBeInTheDocument();
    expect(screen.getByLabelText("Inject")).toBeInTheDocument();
    expect(screen.getByLabelText("Threat Lab")).toBeInTheDocument();
    expect(screen.getByLabelText("Investigation")).toBeInTheDocument();
  });

  it("shows labels when open", () => {
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={true} onMobileClose={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Dashboard")).toBeVisible();
  });

  it("does not render when closed", () => {
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={false} onMobileClose={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.queryByText("Dashboard")).not.toBeInTheDocument();
  });

  it("has accessible navigation", () => {
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={true} onMobileClose={vi.fn()} />
      </MemoryRouter>,
    );
    expect(screen.getByLabelText("Main navigation")).toBeInTheDocument();
  });

  it("active route is highlighted", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Sidebar mobileOpen={true} onMobileClose={vi.fn()} />
      </MemoryRouter>,
    );
    const link = screen.getByLabelText("Dashboard").closest("a");
    expect(link?.className).toContain("hz-nav-item-active");
  });

  it("closes on Escape key", async () => {
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={true} onMobileClose={onClose} />
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("closes on overlay click", async () => {
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <Sidebar mobileOpen={true} onMobileClose={onClose} />
      </MemoryRouter>,
    );
    const user = userEvent.setup();
    const overlay = screen.getByTestId("sidebar-overlay");
    await user.click(overlay);
    expect(onClose).toHaveBeenCalledOnce();
  });
});