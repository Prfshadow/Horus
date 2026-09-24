import * as React from "react";
import { MatrixRain } from "@/components/background/MatrixRain";

/**
 * Ambient landing background: depth-layered glyph rain with atmospheric
 * lighting and a vignette that pulls focus toward the injection gateway.
 * Purely decorative — hidden from assistive tech.
 */
export function MatrixBackground({ reducedMotion = false }: { reducedMotion?: boolean }) {
  return (
    <div className="hz-bg" aria-hidden="true">
      <MatrixRain reducedMotion={reducedMotion} />
      <div className="hz-bg-light" />
      <div className="hz-bg-vignette" />
    </div>
  );
}
