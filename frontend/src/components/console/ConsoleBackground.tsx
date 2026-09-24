import * as React from "react";
import { MatrixRain } from "@/components/background/MatrixRain";

export type ConsoleBackgroundVariant = "dashboard" | "events" | "alerts" | "incidents" | "investigation" | "plain";

const VARIANT_PROPS: Record<Exclude<ConsoleBackgroundVariant, "plain">, { opacity: number; fontSize: number; fallSpeed: number }> = {
  // Landing keeps the full rain; internal pages stay subtle and readable.
  dashboard: { opacity: 0.25, fontSize: 24, fallSpeed: 0.4 },
  events: { opacity: 0.18, fontSize: 28, fallSpeed: 0.35 },
  alerts: { opacity: 0.22, fontSize: 26, fallSpeed: 0.38 },
  incidents: { opacity: 0.22, fontSize: 26, fallSpeed: 0.38 },
  investigation: { opacity: 0.15, fontSize: 30, fallSpeed: 0.3 },
};

/**
 * Shared atmospheric background for internal pages. A single MatrixRain
 * instance at low density/opacity plus a readability vignette. Honors
 * reduced motion (static frame) and never intercepts pointer events.
 */
export function ConsoleBackground({ variant = "dashboard" }: { variant?: ConsoleBackgroundVariant }) {
  const [reducedMotion] = React.useState(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
    try {
      return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch {
      return false;
    }
  });

  if (variant === "plain") {
    return (
      <div className="hzc-bg" aria-hidden="true">
        <div className="hzc-bg-vignette" />
      </div>
    );
  }

  const props = VARIANT_PROPS[variant];
  return (
    <div className="hzc-bg" aria-hidden="true">
      <MatrixRain
        opacity={props.opacity}
        fontSize={props.fontSize}
        fallSpeed={props.fallSpeed}
        reducedMotion={reducedMotion}
      />
      <div className="hzc-bg-vignette" />
    </div>
  );
}
