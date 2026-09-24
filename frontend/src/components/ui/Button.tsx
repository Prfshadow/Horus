import * as React from "react";

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "ghost" | "outline";
  size?: "sm" | "md" | "icon";
};

export function Button({
  className = "",
  variant = "default",
  size = "md",
  ...props
}: ButtonProps) {
  const base =
    "inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 disabled:opacity-50";
  const variants: Record<string, string> = {
    default: "bg-sky-600 text-white hover:bg-sky-700",
    ghost: "bg-transparent text-slate-300 hover:bg-slate-800 hover:text-slate-100",
    outline: "border border-slate-600 bg-transparent text-slate-200 hover:bg-slate-800",
  };
  const sizes: Record<string, string> = {
    sm: "h-8 px-3 text-sm",
    md: "h-9 px-4 text-sm",
    icon: "h-9 w-9",
  };
  return (
    <button className={`${base} ${variants[variant]} ${sizes[size]} ${className}`} {...props} />
  );
}
