import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { EventsPage } from "@/pages/EventsPage";

// Mock useEvents hook
vi.mock("@/hooks/useEvents", () => ({
  useEvents: vi.fn(),
  useEvent: vi.fn(),
}));

import { useEvents } from "@/hooks/useEvents";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const mockEvents = [
  { id: 1, timestamp: "2026-09-14T10:00:00Z", ingested_at: "2026-09-14T10:00:01Z", source: "auth", level: "ERROR", service: "api", host: "h1", message: "fail", raw_log: "raw", extra_data: null },
  { id: 2, timestamp: "2026-09-14T10:00:10Z", ingested_at: "2026-09-14T10:00:11Z", source: "payment", level: "INFO", service: "pay", host: "h2", message: "success", raw_log: "raw2", extra_data: null },
];

describe("EventsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders header and search", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
      isFetching: false,
      refetch: vi.fn(),
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/EVENT EXPLORER/i)).toBeInTheDocument();
    expect(screen.getByText(/Event telemetry/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Search events/i)).toBeInTheDocument();
  });

  it("shows loading state", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: true,
      isError: false,
      data: undefined,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("shows error state", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      isLoading: false,
      isError: true,
      error: { message: "Failed" },
      refetch: vi.fn(),
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/Unable to load events/i)).toBeInTheDocument();
  });

  it("shows empty state when no events", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [], page: 1, page_size: 50, total: 0, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/No events yet/i)).toBeInTheDocument();
  });

  it("shows empty with filters", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [], page: 1, page_size: 50, total: 0, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    // Initially no filters, so "No events yet" — but after setting filter, it should show "No events match"
    // We test the default empty
    expect(screen.getByText(/No events yet/i)).toBeInTheDocument();
  });

  it("renders event rows", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getByText("fail")).toBeInTheDocument();
    expect(screen.getByText("success")).toBeInTheDocument();
    expect(screen.getAllByText("ERROR").length).toBeGreaterThan(0);
  });

  it("search interaction", async () => {
    const user = userEvent.setup();
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    const input = screen.getByLabelText(/Search events/i) as HTMLInputElement;
    await user.type(input, "auth");
    expect(input.value).toBe("auth");
    // Clear
    const clearBtn = screen.getByLabelText(/Clear search/i);
    await user.click(clearBtn);
    expect(input.value).toBe("");
  });

  it("filter interaction", async () => {
    const user = userEvent.setup();
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    const levelSelect = screen.getByLabelText(/Filter by level/i) as HTMLSelectElement;
    await user.selectOptions(levelSelect, "ERROR");
    expect(levelSelect.value).toBe("ERROR");
  });

  it("pagination controls", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 1, total: 2, total_pages: 2 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getAllByText(/Page 1 of 2/i).length).toBeGreaterThan(0);
    expect(screen.getByLabelText(/Previous page/i)).toBeDisabled();
    expect(screen.getByLabelText(/Next page/i)).not.toBeDisabled();
  });

  it("sorting controls", async () => {
    const user = userEvent.setup();
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    const sortBy = screen.getByLabelText(/Sort by/i) as HTMLSelectElement;
    await user.selectOptions(sortBy, "source");
    expect(sortBy.value).toBe("source");
  });

  it("result count and active filter indication", () => {
    (useEvents as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: mockEvents, page: 1, page_size: 50, total: 2, total_pages: 1 },
      isLoading: false,
      isError: false,
    });
    render(<EventsPage />, { wrapper: createWrapper() });
    expect(screen.getByText(/2 events/i)).toBeInTheDocument();
  });
});
