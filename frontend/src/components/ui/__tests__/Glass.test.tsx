import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { GlassPanel, GlassButton, GlassInput, GlassModal } from "@/components/ui/Glass";

describe("GlassPanel", () => {
  it("renders children", () => {
    render(<GlassPanel>Test content</GlassPanel>);
    expect(screen.getByText("Test content")).toBeInTheDocument();
  });

  it("applies variant classes", () => {
    const { container } = render(<GlassPanel variant="elevated">Content</GlassPanel>);
    const panel = container.firstChild as HTMLElement;
    expect(panel).toHaveClass("backdrop-blur-2xl");
  });

  it("applies tilt on mouse move when enabled", () => {
    const { container } = render(<GlassPanel tilt maxTilt={5}>Content</GlassPanel>);
    const panel = container.firstChild as HTMLElement;
    fireEvent.mouseMove(panel, { clientX: 100, clientY: 100 });
    expect(panel.style.transform).toContain("rotateX");
    expect(panel.style.transform).toContain("rotateY");
  });

  it("resets tilt on mouse leave", () => {
    const { container } = render(<GlassPanel tilt maxTilt={5}>Content</GlassPanel>);
    const panel = container.firstChild as HTMLElement;
    fireEvent.mouseMove(panel, { clientX: 100, clientY: 100 });
    fireEvent.mouseLeave(panel);
    expect(panel.style.transform).toContain("rotateX(0deg)");
    expect(panel.style.transform).toContain("rotateY(0deg)");
  });
});

describe("GlassButton", () => {
  it("renders children", () => {
    render(<GlassButton>Click me</GlassButton>);
    expect(screen.getByRole("button", { name: "Click me" })).toBeInTheDocument();
  });

  it("applies variant classes", () => {
    const { container } = render(<GlassButton variant="secondary">Test</GlassButton>);
    const button = container.querySelector("button");
    expect(button).toHaveClass("bg-white/5");
  });

  it("calls onClick handler", () => {
    const handleClick = vi.fn();
    render(<GlassButton onClick={handleClick}>Click</GlassButton>);
    fireEvent.click(screen.getByRole("button"));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it("disables button when disabled prop is true", () => {
    render(<GlassButton disabled>Disabled</GlassButton>);
    expect(screen.getByRole("button", { name: "Disabled" })).toBeDisabled();
  });
});

describe("GlassInput", () => {
  it("renders label", () => {
    render(<GlassInput label="Username" />);
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  it("shows error message", () => {
    render(<GlassInput label="Email" error="Invalid email" />);
    expect(screen.getByText("Invalid email")).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toHaveAttribute("aria-invalid", "true");
  });

  it("generates id from label if not provided", () => {
    render(<GlassInput label="Test Input" />);
    const input = screen.getByLabelText("Test Input");
    expect(input.id).toBe("test-input");
  });
});

describe("GlassModal", () => {
  it("does not render when closed", () => {
    render(<GlassModal isOpen={false} onClose={vi.fn()} title="Test">Test content</GlassModal>);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders when open", () => {
    render(<GlassModal isOpen={true} onClose={vi.fn()} title="Test Modal">Modal content</GlassModal>);
    expect(screen.getByRole("dialog", { name: "Test Modal" })).toBeInTheDocument();
    expect(screen.getByText("Modal content")).toBeInTheDocument();
  });

  it("closes on close button click", () => {
    const onClose = vi.fn();
    render(<GlassModal isOpen={true} onClose={onClose} title="Test">Content</GlassModal>);
    fireEvent.click(screen.getByLabelText("Close"));
    expect(onClose).toHaveBeenCalled();
  });
});