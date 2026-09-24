import * as React from "react";

type BadgeProps = React.HTMLAttributes<HTMLSpanElement> & {
  variant?: "default" | "success" | "warning" | "error" | "info";
};

export function Badge({ className = "", variant = "default", ...props }: BadgeProps) {
  const base = "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium";
  const variants: Record<string, string> = {
    default: "hz-neon-default",
    success: "hz-neon-success",
    warning: "hz-neon-warning",
    error: "hz-neon-error",
    info: "hz-neon-info",
  };
  return <span className={`${base} ${variants[variant]} ${className}`} {...props} />;
}
