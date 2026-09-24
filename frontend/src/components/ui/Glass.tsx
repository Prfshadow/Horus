import * as React from "react";
import { cn } from "@/utils/cn";

interface GlassPanelProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "elevated" | "subtle" | "border-only";
  tilt?: boolean;
  maxTilt?: number;
}

const variantStyles = {
  default: "bg-white/5 backdrop-blur-xl border border-white/10 shadow-[0_8px_32px_rgba(0,0,0,0.4)]",
  elevated: "bg-white/5 backdrop-blur-2xl border border-white/15 shadow-[0_16px_48px_rgba(0,0,0,0.5),0_0_0_1px_rgba(255,255,255,0.05)_inset]",
  subtle: "bg-white/3 backdrop-blur-lg border border-white/5 shadow-[0_4px_24px_rgba(0,0,0,0.3)]",
  "border-only": "bg-transparent backdrop-blur-md border border-white/10 shadow-none",
};

export function GlassPanel({
  className = "",
  variant = "default",
  tilt = false,
  maxTilt = 3,
  children,
  onMouseMove,
  onMouseLeave,
  style,
  ...props
}: GlassPanelProps) {
  const [transform, setTransform] = React.useState({ rotateX: 0, rotateY: 0 });
  const panelRef = React.useRef<HTMLDivElement>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!tilt || !panelRef.current) return;
    const rect = panelRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    const deltaX = (e.clientX - centerX) / (rect.width / 2);
    const deltaY = (e.clientY - centerY) / (rect.height / 2);
    const rotateY = deltaX * maxTilt;
    const rotateX = -deltaY * maxTilt;
    setTransform({ rotateX, rotateY });
    onMouseMove?.(e);
  };

  const handleMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!tilt) return;
    setTransform({ rotateX: 0, rotateY: 0 });
    onMouseLeave?.(e);
  };

  const prefersReducedMotion = React.useMemo(
    () => {
      if (typeof window === "undefined") return false;
      try {
        return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      } catch {
        return false;
      }
    },
    []
  );

  const combinedClassName = cn(
    "rounded-2xl transition-transform duration-300 ease-out",
    variantStyles[variant],
    className
  );

  return (
    <div
      ref={panelRef}
      className={combinedClassName}
      style={{
        transform: prefersReducedMotion || !tilt
          ? undefined
          : `perspective(1000px) rotateX(${transform.rotateX}deg) rotateY(${transform.rotateY}deg)`,
        ...style,
      }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      {...props}
    >
      {children}
    </div>
  );
}

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "elevated" | "subtle";
}

export function GlassCard({
  className = "",
  variant = "default",
  children,
  ...props
}: GlassCardProps) {
  const combinedClassName = cn("p-6", className);
  return (
    <GlassPanel variant={variant} className={combinedClassName} {...props}>
      {children}
    </GlassPanel>
  );
}

export function GlassButton({
  className = "",
  variant = "primary",
  children,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" }) {
  const baseStyles = "inline-flex items-center justify-center gap-2 rounded-xl px-6 py-3 text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50 disabled:opacity-50 disabled:cursor-not-allowed";

  const variantStyles = {
    primary: "bg-cyan-500/20 text-cyan-100 border border-cyan-500/30 hover:bg-cyan-500/30 hover:border-cyan-500/50 active:bg-cyan-500/40",
    secondary: "bg-white/5 text-slate-100 border border-white/10 hover:bg-white/10 hover:border-white/20 active:bg-white/15",
    ghost: "bg-transparent text-slate-300 hover:bg-white/5 hover:text-slate-100 border border-transparent",
  };

  const combinedClassName = cn(baseStyles, variantStyles[variant], className);
  return (
    <button className={combinedClassName} {...props}>
      {children}
    </button>
  );
}

interface GlassInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function GlassInput({ className = "", label, error, id, ...props }: GlassInputProps) {
  const inputId = id || label?.toLowerCase().replace(/\s+/g, "-");
  const inputClassName = cn(
    "w-full rounded-xl bg-white/5 border border-white/10 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500",
    "focus:border-cyan-500/50 focus:outline-none focus:ring-2 focus:ring-cyan-500/20",
    "transition-colors duration-200",
    error && "border-red-500/50 focus:border-red-500 focus:ring-red-500/20",
    className
  );
  return (
    <div className="space-y-1.5">
      {label && (
        <label htmlFor={inputId} className="block text-xs font-medium text-slate-400">
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={inputClassName}
        aria-invalid={!!error}
        aria-describedby={error ? `${inputId}-error` : undefined}
        {...props}
      />
      {error && (
        <p id={`${inputId}-error`} className="text-xs text-red-400" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

export function GlassModal({
  isOpen,
  onClose,
  title,
  children,
  className = "",
}: {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  if (!isOpen) return null;

  const modalClassName = cn("w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col", className);
  const overlayClassName = cn("fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className={overlayClassName} onClick={onClose} aria-hidden="true" />
      <GlassPanel variant="elevated" className={modalClassName}>
        <div className="flex items-center justify-between border-b border-white/10 px-6 py-4">
          <h2 id="modal-title" className="text-lg font-semibold text-slate-100">
            {title}
          </h2>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-slate-100 hover:bg-white/5 transition-colors"
            aria-label="Close"
          >
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-6">
          {children}
        </div>
      </GlassPanel>
    </div>
  );
}