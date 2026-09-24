import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EventDetailPage } from "@/pages/EventDetailPage";

vi.mock("@/hooks/useEvents", () => ({
  useEvent: vi.fn(),
}));

import { useEvent } from "@/hooks/useEvents";

function createWrapper(initialPath: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/events/:id" element={children} />
          <Route path="/events" element={<div>Events</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const mockEvent = {
  id: 1,
  timestamp: "2026-09-14T10:00:00Z",
  ingested_at: "2026-09-14T10:00:05Z",
  source: "auth",
  level: "ERROR",
  service: "api",
  host: "h1",
  message: "fail message",
  raw_log: "raw log content with <script>alert('xss')</script>",
  extra_data: { ip: "10.0.0.1", user: "test" },
};

describe("EventDetailPage", () => {
  it("renders loading state", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({ isLoading: true, isError: false });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("renders error state for not found", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: true,
      error: { status: 404, message: "Not found" },
      refetch: vi.fn(),
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/999") });
    expect(screen.getByText(/Event not found/i)).toBeInTheDocument();
  });

  it("renders event details", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: false,
      data: mockEvent,
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    expect(screen.getByText("Event #1")).toBeInTheDocument();
    expect(screen.getByText("fail message")).toBeInTheDocument();
    expect(screen.getByText("auth")).toBeInTheDocument();
    expect(screen.getAllByText("ERROR").length).toBeGreaterThan(0);
  });

  it("renders raw log safely (no HTML execution)", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: false,
      data: mockEvent,
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    // Raw log should be rendered as text, not HTML
    expect(screen.getByText(/raw log content/i)).toBeInTheDocument();
    // The script tag should be escaped, not executed
    const codeEl = screen.getByText(/<script>/i);
    expect(codeEl).toBeInTheDocument();
    expect(codeEl.tagName).toBe("CODE");
  });

  it("renders extra_data", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: false,
      data: mockEvent,
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    expect(screen.getByText(/"ip": "10.0.0.1"/)).toBeInTheDocument();
  });

  it("handles empty extra_data", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: false,
      data: { ...mockEvent, extra_data: null },
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    expect(screen.getByText(/No structured data/i)).toBeInTheDocument();
  });

  it("handles invalid event ID", () => {
    render(<EventDetailPage />, { wrapper: createWrapper("/events/invalid") });
    expect(screen.getByText(/Invalid event ID/i)).toBeInTheDocument();
  });

  it("has back link to events", () => {
    (useEvent as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: false,
      data: mockEvent,
    });
    render(<EventDetailPage />, { wrapper: createWrapper("/events/1") });
    expect(screen.getByText(/Back to Events/i).closest("a")?.getAttribute("href")).toBe("/events");
  });
});
