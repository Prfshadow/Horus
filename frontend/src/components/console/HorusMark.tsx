/**
 * Compact cybernetic eye mark — the same optic as the landing hero eye,
 * simplified for small sizes: almond lids, glowing iris, dark pupil,
 * HUD reticle ticks. One identity, shared everywhere.
 */
export function HorusMark({ className = "hz-brand-eye" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 120 70" aria-hidden="true" focusable="false">
      {/* HUD reticle ticks */}
      <g
        className="hz-mark-reticle"
        fill="none"
        stroke="rgba(76, 224, 182, 0.55)"
        strokeWidth="3"
        strokeLinecap="round"
      >
        <line x1="60" y1="4" x2="60" y2="10" />
        <line x1="60" y1="60" x2="60" y2="66" />
        <line x1="32" y1="35" x2="38" y2="35" />
        <line x1="82" y1="35" x2="88" y2="35" />
      </g>
      {/* Sclera bed */}
      <path
        className="hz-mark-sclera"
        d="M16 35 Q60 14 104 33 Q80 52 60 53 Q40 52 16 35 Z"
        fill="rgba(240, 248, 245, 0.08)"
      />
      {/* Glowing iris */}
      <ellipse
        className="hz-mark-iris"
        cx="60"
        cy="35"
        rx="13"
        ry="13"
        fill="#1cc8a0"
      />
      <ellipse
        className="hz-mark-iris-ring"
        cx="60"
        cy="35"
        rx="13"
        ry="13"
        fill="none"
        stroke="rgba(143, 245, 214, 0.8)"
        strokeWidth="2"
      />
      {/* Pupil + catchlight */}
      <ellipse className="hz-mark-pupil" cx="60" cy="35" rx="5.5" ry="5.5" fill="#020607" />
      <ellipse
        className="hz-mark-glare"
        cx="56"
        cy="31"
        rx="2.4"
        ry="1.8"
        fill="rgba(255, 255, 255, 0.9)"
      />
      {/* Lids over the iris */}
      <path
        className="hz-mark-lid"
        d="M12 35 Q60 10 108 32"
        fill="none"
        stroke="rgba(233, 245, 242, 0.9)"
        strokeWidth="4"
        strokeLinecap="round"
      />
      <path
        className="hz-mark-lid"
        d="M14 37 Q36 52 60 53 Q84 52 106 33"
        fill="none"
        stroke="rgba(233, 245, 242, 0.7)"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}
