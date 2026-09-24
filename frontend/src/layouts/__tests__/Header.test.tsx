import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Header } from "@/layouts/Header";
import * as useHealthModule from "@/hooks/useHealth";

function renderHeader(props: { onMenuToggle?: () => void } = {}) {
  return render(
    <MemoryRouter>
      <Header {...props} />
    </MemoryRouter>,
  );
}

describe("Header", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders HORUS branding", () => {
    vi.spyOn(useHealthModule, "useHealth").mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
    } as never);
    renderHeader();
    expect(screen.getByText("HORUS")).toBeInTheDocument();
    expect(screen.getByText("Log Intelligence")).toBeInTheDocument();
  });

  it("shows loading state", () => {
    vi.spyOn(useHealthModule, "useHealth").mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
    } as never);
    renderHeader();
    expect(screen.getByText(/Checking/i)).toBeInTheDocument();
  });

  it("shows healthy state", () => {
    vi.spyOn(useHealthModule, "useHealth").mockReturnValue({
      data: { status: "ok", app: "Horus", env: "dev", database: "connected" },
      isLoading: false,
      isError: false,
    } as never);
    renderHeader();
    expect(screen.getByText("System operational")).toBeInTheDocument();
  });

  it("shows error state", () => {
    vi.spyOn(useHealthModule, "useHealth").mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
      error: { message: "down" },
    } as never);
    renderHeader();
    expect(screen.getByText("Backend unavailable")).toBeInTheDocument();
  });

  it("has accessible menu toggle", () => {
    vi.spyOn(useHealthModule, "useHealth").mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
    } as never);
    const onToggle = vi.fn();
    renderHeader({ onMenuToggle: onToggle });
    expect(screen.getByLabelText("Toggle navigation")).toBeInTheDocument();
  });
});
