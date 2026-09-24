import * as React from "react";

/**
 * The watching-eye emblem — a cybernetic eye in the HORUS teal/cyan theme.
 *
 * A natural almond eye (lid fold with a soft crease above, gentle lower
 * lid) with a hacker-style iris: dark limbal ring, glowing teal core,
 * fine radial micro-detail, and a fixed HUD reticle ring with cardinal
 * ticks that the iris moves inside of like a targeting optic.
 *
 * Blink is structural: lids + eyeball live in one `.hz-eyeball` group that
 * squashes together, so the pupil genuinely hides behind the closing lids.
 *
 * Tracking (unchanged, proven system):
 * - CONTINUOUS global pointer tracking: a single `pointermove` (+ `mousemove`
 *   fallback) listener on `window` updates a target offset; a single
 *   `requestAnimationFrame` loop lerps the iris toward that target.
 *   No click required. Listens globally so the eye tracks even when the
 *   cursor is over title / panels / nav / empty space.
 * - Iris stays clamped inside the eye (max radius).
 * - Cursor leaves window -> iris eases back to center.
 * - Natural randomized blink cycle, preserved during tracking.
 * - Idle: subtle breathing glow after 3s of no movement.
 * - Touch / coarse pointers: iris stays centered, no errors.
 * - Respects prefers-reduced-motion.
 */
export function HorusEye({ reduceMotion = false }: { reduceMotion?: boolean }) {
  const [blinking, setBlinking] = React.useState(false);
  const svgRef = React.useRef<SVGSVGElement>(null);
  const irisRef = React.useRef<SVGGElement>(null);

  // Blink cycle — randomized intervals, natural feel. Untouched by tracking.
  React.useEffect(() => {
    if (reduceMotion) return;
    let alive = true;
    let first = 0;
    let second = 0;

    const schedule = () => {
      const baseDelay = 3000 + Math.random() * 8000; // 3-11s between blinks
      const blinkDuration = 150 + Math.random() * 100; // 150-250ms blink
      first = window.setTimeout(() => {
        if (!alive) return;
        setBlinking(true);
        second = window.setTimeout(() => {
          if (!alive) return;
          setBlinking(false);
          // Occasional double-blink (15% chance)
          if (Math.random() < 0.15) {
            setTimeout(() => {
              if (!alive) return;
              setBlinking(true);
              setTimeout(() => {
                if (!alive) return;
                setBlinking(false);
                schedule();
              }, 100 + Math.random() * 80);
            }, 200 + Math.random() * 200);
          } else {
            schedule();
          }
        }, blinkDuration);
      }, baseDelay);
    };
    schedule();

    return () => {
      alive = false;
      window.clearTimeout(first);
      window.clearTimeout(second);
    };
  }, [reduceMotion]);

  // Continuous cursor tracking: pointermove -> target, RAF -> smooth approach.
  // Uses refs only (no setState per frame) so there is exactly one loop and
  // no re-render churn. Cleans up everything on unmount.
  React.useEffect(() => {
    if (reduceMotion) return;
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const svg = svgRef.current;
    const iris = irisRef.current;
    if (!svg || !iris) return;

    const finePointer =
      window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    const target = { x: 0, y: 0 };
    const current = { x: 0, y: 0 };
    let lastMove = 0; // 0 = never moved -> idle/centered
    let raf = 0;
    let disposed = false;
    let breath = 0;
    const IDLE_MS = 3000;
    const MAX_RADIUS = 0.32;
    const PX_X = 18;
    const PX_Y = 12.5;
    const LERP = 0.22;

    const updateTarget = (clientX: number, clientY: number) => {
      const rect = svg.getBoundingClientRect();
      if (!rect || rect.width === 0 || rect.height === 0) return;
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = (clientX - cx) / (rect.width / 2);
      const dy = (clientY - cy) / (rect.height / 2);
      const dist = Math.sqrt(dx * dx + dy * dy);
      const clampedX = dist > MAX_RADIUS ? (dx / dist) * MAX_RADIUS : dx;
      const clampedY = dist > MAX_RADIUS ? (dy / dist) * MAX_RADIUS : dy;
      target.x = clampedX * PX_X;
      target.y = clampedY * PX_Y;
      lastMove = performance.now();
    };

    const onPointerMove = (e: PointerEvent) => {
      updateTarget(e.clientX, e.clientY);
    };
    const onMouseMove = (e: MouseEvent) => {
      updateTarget(e.clientX, e.clientY);
    };
    // Cursor left the window -> ease back to center.
    const onLeaveWindow = () => {
      target.x = 0;
      target.y = 0;
      lastMove = 0;
    };

    const loop = (now: number) => {
      if (disposed) return;
      raf = requestAnimationFrame(loop);
      if (document.hidden) return;

      const idle = lastMove === 0 || now - lastMove > IDLE_MS;
      if (idle) {
        // Ease target itself back to center so the eye settles naturally.
        target.x += (0 - target.x) * 0.02;
        target.y += (0 - target.y) * 0.02;
        breath = (breath + 0.0035) % (Math.PI * 2);
      }
      current.x += (target.x - current.x) * LERP;
      current.y += (target.y - current.y) * LERP;
      // Snap tiny residuals to avoid perpetual sub-pixel drift.
      if (Math.abs(target.x - current.x) < 0.01) current.x = target.x;
      if (Math.abs(target.y - current.y) < 0.01) current.y = target.y;

      iris.style.transform = `translate(${current.x.toFixed(2)}px, ${current.y.toFixed(2)}px)`;

      // Idle breathing glow applied directly (no React state churn).
      if (idle) {
        const glow = 0.15 + Math.sin(breath) * 0.08;
        svg.style.filter = `drop-shadow(0 0 ${(12 + glow * 20).toFixed(1)}px rgba(76, 224, 182, ${(0.25 + glow * 0.3).toFixed(3)}))`;
      } else if (svg.style.filter !== "") {
        svg.style.filter = "";
      }
    };

    if (finePointer) {
      window.addEventListener("pointermove", onPointerMove, { passive: true });
      // Fallback for browsers without PointerEvent.
      window.addEventListener("mousemove", onMouseMove, { passive: true });
      document.documentElement.addEventListener("mouseleave", onLeaveWindow);
      document.addEventListener("mouseleave", onLeaveWindow);
      window.addEventListener("blur", onLeaveWindow);
      document.addEventListener("pointerleave", onLeaveWindow);
      document.addEventListener("pointercancel", onLeaveWindow);
    }
    raf = requestAnimationFrame(loop);

    return () => {
      disposed = true;
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("mousemove", onMouseMove);
      document.documentElement.removeEventListener("mouseleave", onLeaveWindow);
      document.removeEventListener("mouseleave", onLeaveWindow);
      window.removeEventListener("blur", onLeaveWindow);
      document.removeEventListener("pointerleave", onLeaveWindow);
      document.removeEventListener("pointercancel", onLeaveWindow);
      cancelAnimationFrame(raf);
    };
  }, [reduceMotion]);

  // Fine radial micro-detail etched into the iris.
  const microTicks = React.useMemo(
    () =>
      Array.from({ length: 24 }, (_, i) => {
        const a = (i / 24) * Math.PI * 2;
        const long = i % 2 === 0;
        const r1 = long ? 11.5 : 13;
        const r2 = 15.5;
        return {
          x1: 110 + Math.cos(a) * r1,
          y1: 66 + Math.sin(a) * r1,
          x2: 110 + Math.cos(a) * r2,
          y2: 66 + Math.sin(a) * r2,
          opacity: long ? 0.5 : 0.28,
        };
      }),
    [],
  );

  return (
    <svg
      ref={svgRef}
      className={`hz-emblem${blinking ? " is-blink" : ""}`}
      viewBox="0 0 220 140"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <filter id="eye-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        {/* Glowing iris core — bright center fading to a deep edge. */}
        <radialGradient id="iris-gradient" cx="50%" cy="38%" r="62%" fx="44%" fy="34%">
          <stop offset="0%" stopColor="#8ff5d6" stopOpacity="0.98" />
          <stop offset="30%" stopColor="#2ae8c0" stopOpacity="0.95" />
          <stop offset="62%" stopColor="#14b894" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#076b54" stopOpacity="0.9" />
        </radialGradient>
      </defs>

      <g className="hz-eye-group" filter="url(#eye-glow)">
        {/* Soft lid crease above the eye — what makes it read as a real eye. */}
        <path
          className="hz-crease"
          d="M54 58 Q110 30 166 53"
          fill="none"
          stroke="rgba(233, 245, 242, 0.35)"
          strokeWidth="1.5"
          strokeLinecap="round"
        />

        {/* The blinking eyeball: sclera + tracking iris + reticle + lids
            squash as one, so the pupil genuinely hides when the eye closes. */}
        <g className="hz-eyeball">
          {/* Ambient halo glow behind the whole optic. */}
          <ellipse
            className="hz-aura-big"
            cx="110"
            cy="66"
            rx="46"
            ry="37"
            fill="rgba(76, 224, 182, 0.05)"
          />

          {/* Sclera — faint almond bed. */}
          <path
            className="hz-sclera"
            d="M40 68 Q110 40 180 62 Q146 86 110 88 Q74 86 40 68 Z"
            fill="rgba(240, 248, 245, 0.07)"
          />

          {/* Iris group — moved directly via ref (no React re-render). */}
          <g ref={irisRef} className="hz-eye-iris">
            {/* Aura disc behind the iris. */}
            <ellipse
              className="hz-aura"
              cx="110"
              cy="66"
              rx="30"
              ry="28"
              fill="rgba(76, 224, 182, 0.07)"
            />

            {/* The iris. */}
            <ellipse
              className="hz-iris"
              cx="110"
              cy="66"
              rx="20"
              ry="20"
              fill="url(#iris-gradient)"
            />

            {/* Etched micro-detail. */}
            <g className="hz-iris-detail" stroke="rgba(4, 20, 17, 0.4)" strokeWidth="0.8">
              {microTicks.map((t, i) => (
                <line key={i} x1={t.x1} y1={t.y1} x2={t.x2} y2={t.y2} opacity={t.opacity} />
              ))}
              <ellipse cx="110" cy="66" rx="9.5" ry="9.5" fill="none" />
            </g>

            {/* Dark limbal ring — the realistic outer edge. */}
            <ellipse
              className="hz-limbal"
              cx="110"
              cy="66"
              rx="20"
              ry="20"
              fill="none"
              stroke="rgba(2, 10, 8, 0.65)"
              strokeWidth="2.5"
            />

            {/* Bright inner accent ring — the charged core look. */}
            <ellipse
              className="hz-core-ring"
              cx="110"
              cy="66"
              rx="12"
              ry="12"
              fill="none"
              stroke="rgba(143, 245, 214, 0.75)"
              strokeWidth="1"
            />

            {/* Pupil — dark core with a faint teal rim. */}
            <ellipse
              className="hz-pupil"
              cx="110"
              cy="66"
              rx="8"
              ry="8"
              fill="#020607"
              stroke="rgba(76, 224, 182, 0.35)"
              strokeWidth="1"
            />

            {/* Primary catchlight — the spark of life. */}
            <ellipse
              className="hz-catchlight hz-catchlight-primary"
              cx="101"
              cy="57"
              rx="4.5"
              ry="3.6"
              fill="rgba(255, 255, 255, 0.92)"
              opacity="0.9"
            />

            {/* Secondary teal reflection. */}
            <ellipse
              className="hz-catchlight hz-catchlight-secondary"
              cx="119"
              cy="74"
              rx="2"
              ry="1.5"
              fill="rgba(76, 224, 182, 0.65)"
              opacity="0.55"
            />
          </g>

          {/* Fixed HUD reticle — stays put while the iris moves inside it,
              like a targeting optic acquiring the cursor. */}
          <g className="hz-reticle" fill="none" stroke="rgba(76, 224, 182, 0.45)" strokeWidth="1.5">
            <ellipse cx="110" cy="66" rx="25" ry="25" strokeWidth="1" opacity="0.7" />
            <line x1="110" y1="34" x2="110" y2="39" strokeLinecap="round" />
            <line x1="110" y1="93" x2="110" y2="98" strokeLinecap="round" />
            <line x1="78" y1="66" x2="83" y2="66" strokeLinecap="round" />
            <line x1="137" y1="66" x2="142" y2="66" strokeLinecap="round" />
          </g>

          {/* Counter-rotating orbit rings — slow HUD gyroscopes the iris
              moves inside of. Fixed (not tracking) siblings of the iris. */}
          <g className="hz-orbit" fill="none" stroke="rgba(76, 224, 182, 0.35)" strokeWidth="1.2">
            <ellipse cx="110" cy="66" rx="29" ry="29" strokeDasharray="4 6" />
          </g>
          <g className="hz-orbit-rev" fill="none" stroke="rgba(76, 224, 182, 0.18)" strokeWidth="1">
            <ellipse cx="110" cy="66" rx="33.5" ry="33.5" strokeDasharray="2 9" />
          </g>

          {/* Upper lid drawn OVER the iris so it tucks behind it, and the
              closing lids cover the pupil on blink. */}
          <path
            className="hz-lid hz-lid-upper"
            d="M34 68 Q110 32 186 62"
            fill="none"
            stroke="rgba(233, 245, 242, 0.85)"
            strokeWidth="3.5"
            strokeLinecap="round"
          />

          {/* Lower lid, drawn over the iris bed. */}
          <path
            className="hz-lid hz-lid-lower"
            d="M38 70 Q72 90 110 92 Q148 90 182 63"
            fill="none"
            stroke="rgba(233, 245, 242, 0.65)"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        </g>
      </g>
    </svg>
  );
}
