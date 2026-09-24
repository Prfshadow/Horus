/**
 * Shared, smoothed pointer state for the landing experience.
 *
 * Written by `useLandingParallax`, read directly by the matrix-rain
 * renderer each animation frame (no React re-renders, no per-frame DOM
 * reads). Values are normalized to [-1, 1].
 */
export const landingPointer = {
  x: 0,
  y: 0,
  tx: 0,
  ty: 0,
};

export function resetLandingPointer(): void {
  landingPointer.x = 0;
  landingPointer.y = 0;
  landingPointer.tx = 0;
  landingPointer.ty = 0;
}
