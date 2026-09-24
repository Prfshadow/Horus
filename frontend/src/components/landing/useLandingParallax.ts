import * as React from "react";
import { landingPointer, resetLandingPointer } from "@/components/landing/landingPointer";

function supportsFinePointer(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  try {
    return window.matchMedia("(hover: hover) and (pointer: fine)").matches;
  } catch {
    return false;
  }
}

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  try {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

/**
 * Tracks the pointer and publishes smoothed --mx/--my CSS vars on <html>
 * for parallax layers (hero, gateway tilt, eye iris). No-ops on touch
 * devices and when reduced motion is requested. Cleans up on unmount.
 */
export function useLandingParallax(enabled = true): void {
  React.useEffect(() => {
    if (!enabled || !supportsFinePointer() || prefersReducedMotion()) return;

    const root = document.documentElement;
    let raf = 0;

    const onMove = (e: PointerEvent) => {
      landingPointer.tx = (e.clientX / window.innerWidth) * 2 - 1;
      landingPointer.ty = (e.clientY / window.innerHeight) * 2 - 1;
    };

    const loop = () => {
      landingPointer.x += (landingPointer.tx - landingPointer.x) * 0.06;
      landingPointer.y += (landingPointer.ty - landingPointer.y) * 0.06;
      root.style.setProperty("--mx", landingPointer.x.toFixed(4));
      root.style.setProperty("--my", landingPointer.y.toFixed(4));
      raf = requestAnimationFrame(loop);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    raf = requestAnimationFrame(loop);

    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(raf);
      root.style.removeProperty("--mx");
      root.style.removeProperty("--my");
      resetLandingPointer();
    };
  }, [enabled]);
}

export { prefersReducedMotion };
