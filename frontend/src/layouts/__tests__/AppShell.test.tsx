import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AppShell } from "@/layouts/AppShell";

vi.mock("@/hooks/useHealth", () => ({
  useHealth: () => ({ data: { status: "ok", database: "connected" }, isLoading: false, isError: false }),
}));

function renderShell() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/dashboard"]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<div>Dashboard Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AppShell", () => {
  it("renders header and content", async () => {
    renderShell();
    expect(screen.getByText("HORUS")).toBeInTheDocument();
    expect(screen.getByText("Dashboard Content")).toBeInTheDocument();
  });

  it("opens mobile drawer via header menu", async () => {
    const user = userEvent.setup();
    renderShell();
    // Drawer closed by default
    expect(screen.queryByLabelText("Main navigation")).not.toBeInTheDocument();
    const menuBtn = screen.getByLabelText("Toggle navigation");
    await user.click(menuBtn);
    expect(screen.getByLabelText("Main navigation")).toBeInTheDocument();
  });

  it("closes drawer on overlay click", async () => {
    const user = userEvent.setup();
    renderShell();
    await user.click(screen.getByLabelText("Toggle navigation"));
    expect(screen.getByLabelText("Main navigation")).toBeInTheDocument();
    await user.click(screen.getByTestId("sidebar-overlay"));
    expect(screen.queryByLabelText("Main navigation")).not.toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    renderShell();
    // Open drawer
    await user.click(screen.getByLabelText("Toggle navigation"));
    expect(screen.getByLabelText("Main navigation")).toBeInTheDocument();
    // Press Escape
    await user.keyboard("{Escape}");
    expect(screen.queryByLabelText("Main navigation")).not.toBeInTheDocument();
    // Should still render (no crash)
    expect(screen.getByText("HORUS")).toBeInTheDocument();
  });
});
