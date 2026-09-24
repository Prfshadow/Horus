import * as React from "react";
import { landingPointer } from "@/components/landing/landingPointer";

/**
 * Depth-banded glyph rain rendered on canvas.
 *
 * Far columns are small, slow and dim; near columns are large, fast and
 * bright. Each column drifts horizontally with the shared landing pointer
 * (multiplane parallax). Respects prefers-reduced-motion by rendering a
 * single frozen frame. Cleans up animation frame + listeners on unmount.
 *
 * Trail fix: Instead of accumulating semi-transparent fills (which never
 * fully fade), each column maintains its own trail of recent positions.
 * Trails have a fixed max length and fade out naturally per-frame.
 */

const GLYPHS = "0123456789ABCDEFabcdef<>[]{}/\\|=+-#$%&";
const TRAIL_LENGTH = 18; // max trail segments per column
const TRAIL_FADE = 0.055; // alpha decay per segment

interface Band {
  gap: number;
  fontMin: number;
  fontMax: number;
  speedMin: number;
  speedMax: number;
  alphaMin: number;
  alphaMax: number;
  depthMin: number;
  depthMax: number;
  parallax: number;
}

interface TrailSegment {
  y: number;
  char: string;
  alpha: number;
}

interface Column {
  x: number;
  baseX: number;
  y: number;
  depth: number;
  speed: number;
  fontCss: string;
  fontH: number;
  fill: string;
  head: string;
  trail: TrailSegment[];
  parallax: number;
}

const DESKTOP_BANDS: Band[] = [
  { gap: 19, fontMin: 10, fontMax: 12, speedMin: 0.5, speedMax: 1.2, alphaMin: 0.06, alphaMax: 0.15, depthMin: 0.05, depthMax: 0.3, parallax: 30 },
  { gap: 33, fontMin: 13, fontMax: 17, speedMin: 1.1, speedMax: 2.2, alphaMin: 0.13, alphaMax: 0.28, depthMin: 0.35, depthMax: 0.65, parallax: 30 },
  { gap: 55, fontMin: 18, fontMax: 24, speedMin: 2.0, speedMax: 3.6, alphaMin: 0.24, alphaMax: 0.52, depthMin: 0.7, depthMax: 1.0, parallax: 30 },
];

const MOBILE_BANDS: Band[] = [
  { gap: 26, fontMin: 9, fontMax: 11, speedMin: 0.5, speedMax: 1.0, alphaMin: 0.05, alphaMax: 0.13, depthMin: 0.05, depthMax: 0.3, parallax: 18 },
  { gap: 44, fontMin: 12, fontMax: 15, speedMin: 1.0, speedMax: 1.9, alphaMin: 0.1, alphaMax: 0.24, depthMin: 0.35, depthMax: 0.65, parallax: 18 },
  { gap: 78, fontMin: 16, fontMax: 20, speedMin: 1.7, speedMax: 3.0, alphaMin: 0.2, alphaMax: 0.45, depthMin: 0.7, depthMax: 1.0, parallax: 18 },
];

const rand = (min: number, max: number): number => min + Math.random() * (max - min);

function isSmallScreen(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  try {
    return window.matchMedia("(max-width: 768px)").matches;
  } catch {
    return false;
  }
}

interface MatrixRainProps {
  className?: string;
  /** Master opacity multiplier for the canvas element. */
  opacity?: number;
  /** Kept for backward compatibility; scales overall glyph density speed. */
  fontSize?: number;
  fallSpeed?: number;
  color?: string;
  reducedMotion?: boolean;
}

export function MatrixRain({
  className = "",
  opacity = 1,
  fontSize = 14,
  fallSpeed = 1,
  color,
  reducedMotion = false,
}: MatrixRainProps) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);

  React.useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let columns: Column[] = [];
    let w = 0;
    let h = 0;
    let raf = 0;
    let last = performance.now();
    let resizeTimer = 0;
    let disposed = false;

    const speedScale = fallSpeed <= 0 ? 1 : fallSpeed;
    const densityScale = fontSize >= 18 ? 1.25 : fontSize <= 10 ? 0.8 : 1;

    const build = () => {
      columns = [];
      const bands = (isSmallScreen() ? MOBILE_BANDS : DESKTOP_BANDS).map((b) => ({
        ...b,
        gap: b.gap * densityScale,
      }));
      for (const b of bands) {
        const count = Math.max(3, Math.round(w / b.gap));
        for (let i = 0; i < count; i++) {
          const alpha = rand(b.alphaMin, b.alphaMax);
          const size = Math.round(rand(b.fontMin, b.fontMax));
          const baseX = ((i + rand(0.2, 0.8)) / count) * w;
          columns.push({
            x: baseX,
            baseX,
            y: rand(-h, h),
            depth: rand(b.depthMin, b.depthMax),
            speed: rand(b.speedMin, b.speedMax) * speedScale,
            fontCss: `500 ${size}px "JetBrains Mono", ui-monospace, monospace`,
            fontH: size,
            fill: color ?? `hsla(167, 72%, 62%, ${alpha.toFixed(2)})`,
            head: `hsla(167, 90%, 80%, ${Math.min(1, alpha + 0.32).toFixed(2)})`,
            trail: [],
            parallax: b.parallax,
          });
        }
      }
    };

    const drawStatic = () => {
      ctx.clearRect(0, 0, w, h);
      for (const c of columns) {
        for (let i = 0; i < 7; i++) {
          ctx.font = c.fontCss;
          ctx.globalAlpha = Math.max(0, 1 - i * 0.16);
          ctx.fillStyle = i === 0 ? c.head : c.fill;
          ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0] ?? "0", c.x, c.y - i * c.fontH * 1.05);
        }
      }
      ctx.globalAlpha = 1;
    };

    const frame = (now: number) => {
      if (disposed) return;
      raf = requestAnimationFrame(frame);
      if (document.hidden) {
        last = now;
        return;
      }
      const dt = Math.min(now - last, 50) / 16.666;
      last = now;

      // Clear canvas completely each frame - no accumulation
      ctx.clearRect(0, 0, w, h);

      for (const c of columns) {
        c.y += c.speed * dt;
        const px = c.baseX + landingPointer.x * (c.depth - 0.5) * c.parallax;
        c.x = px;

        // Add current position to trail
        c.trail.unshift({
          y: c.y,
          char: GLYPHS[(Math.random() * GLYPHS.length) | 0] ?? "0",
          alpha: 1,
        });

        // Limit trail length and fade
        if (c.trail.length > TRAIL_LENGTH) {
          c.trail.pop();
        }

        // Reset column when it goes off screen
        if (c.y - c.fontH * TRAIL_LENGTH > h) {
          c.y = rand(-160, -20);
          c.trail = [];
        }

        // Draw head (brightest)
        ctx.font = c.fontCss;
        ctx.fillStyle = c.head;
        ctx.globalAlpha = 1;
        ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0] ?? "0", px, c.y);

        // Draw trail segments with fading alpha
        ctx.font = c.fontCss;
        ctx.fillStyle = c.fill;
        for (let i = 0; i < c.trail.length; i++) {
          const seg = c.trail[i];
          if (!seg) continue;
          seg.alpha = Math.max(0, seg.alpha - TRAIL_FADE);
          if (seg.alpha <= 0) continue;
          ctx.globalAlpha = seg.alpha;
          ctx.fillText(seg.char, px, seg.y - i * c.fontH * 1.05);
        }
      }
      ctx.globalAlpha = 1;
    };

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.75);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      build();
      if (reducedMotion) drawStatic();
    };

    const onResize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(resize, 150);
    };

    resize();
    window.addEventListener("resize", onResize);
    if (!reducedMotion) {
      raf = requestAnimationFrame(frame);
    }

    return () => {
      disposed = true;
      window.removeEventListener("resize", onResize);
      window.clearTimeout(resizeTimer);
      cancelAnimationFrame(raf);
    };
  }, [fontSize, fallSpeed, color, reducedMotion]);

  return (
    <canvas
      ref={canvasRef}
      className={`hz-rain ${className}`}
      aria-hidden="true"
      style={{ opacity }}
    />
  );
}