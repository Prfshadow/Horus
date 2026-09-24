import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { IngestPanel, parseLogLines, chunkLines } from "@/components/dashboard/IngestPanel";

vi.mock("@/hooks/useIngest", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/hooks/useIngest")>();
  return { ...actual, useIngestLogs: vi.fn() };
});

import { useIngestLogs } from "@/hooks/useIngest";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe("parseLogLines", () => {
  it("splits lines and drops empties", () => {
    expect(parseLogLines('a\n\n  \nb\r\nc')).toEqual(["a", "b", "c"]);
  });

  it("handles empty input", () => {
    expect(parseLogLines("   \n ")).toEqual([]);
  });
});

describe("chunkLines", () => {
  it("chunks evenly and with remainder", () => {
    expect(chunkLines([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });
});

describe("IngestPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync: vi.fn().mockResolvedValue({ accepted: 0, failed: 0, results: [] }),
      isPending: false,
      reset: vi.fn(),
    });
  });

  it("renders paste box, file input and inject button", () => {
    render(<IngestPanel />, { wrapper: createWrapper() });
    expect(screen.getByRole("heading", { name: /Inject Logs/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Paste log lines/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Upload log file/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Inject logs/i })).toBeInTheDocument();
  });

  it("shows an error when submitted empty", async () => {
    const user = userEvent.setup();
    render(<IngestPanel />, { wrapper: createWrapper() });
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    expect(await screen.findByText(/Paste some log lines/i)).toBeInTheDocument();
  });

  it("submits pasted lines and shows stored count", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockResolvedValue({ accepted: 2, failed: 0, results: [] });
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    render(<IngestPanel />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), "line one\nline two");
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await waitFor(() => {
      expect(mutateAsync).toHaveBeenCalledWith({ logs: ["line one", "line two"], source: "auth-service" });
    });
    expect(await screen.findByText(/Stored/i)).toBeInTheDocument();
  });

  it("reads a file and submits its lines", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockResolvedValue({ accepted: 3, failed: 0, results: [] });
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    render(<IngestPanel />, { wrapper: createWrapper() });
    const file = new File(["a\nb\nc"], "logs.txt", { type: "text/plain" });
    await user.upload(screen.getByLabelText(/Upload log file/i), file);
    expect(await screen.findByText(/logs\.txt/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await waitFor(() => {
      expect(mutateAsync).toHaveBeenCalledWith({ logs: ["a", "b", "c"], source: "auth-service" });
    });
  });

  it("renders raw log content as text, not HTML", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockResolvedValue({ accepted: 1, failed: 0, results: [] });
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    render(<IngestPanel />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), '<script>alert("xss")</script>');
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await waitFor(() => {
      expect(mutateAsync).toHaveBeenCalledWith({ logs: ['<script>alert("xss")</script>'], source: "auth-service" });
    });
    expect(document.querySelector("script")).toBeNull();
  });

  it("calls onIngested with stored event IDs after successful upload", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockResolvedValue({
      accepted: 2,
      failed: 0,
      results: [
        { index: 0, event_id: 101, status: "stored" },
        { index: 1, event_id: 102, status: "stored" },
      ],
    });
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    const onIngested = vi.fn();
    render(<IngestPanel onIngested={onIngested} />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), "line one\nline two");
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await waitFor(() => {
      expect(onIngested).toHaveBeenCalledWith({ accepted: 2, failed: 0, eventIds: [101, 102] });
    });
  });

  it("does not call onIngested when ingestion fails", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockRejectedValue(new Error("network down"));
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    const onIngested = vi.fn();
    render(<IngestPanel onIngested={onIngested} />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), "line one");
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await screen.findByText(/network down/i);
    expect(onIngested).not.toHaveBeenCalled();
  });

  it("does not call onIngested when nothing was stored", async () => {
    const user = userEvent.setup();
    const mutateAsync = vi.fn().mockResolvedValue({ accepted: 0, failed: 2, results: [] });
    (useIngestLogs as unknown as ReturnType<typeof vi.fn>).mockReturnValue({
      mutateAsync,
      isPending: false,
      reset: vi.fn(),
    });
    const onIngested = vi.fn();
    render(<IngestPanel onIngested={onIngested} />, { wrapper: createWrapper() });
    await user.type(screen.getByLabelText(/Paste log lines/i), "bad line\nworse line");
    await user.click(screen.getByRole("button", { name: /Inject logs/i }));
    await screen.findByText(/failed to parse/i);
    expect(onIngested).not.toHaveBeenCalled();
  });
});
