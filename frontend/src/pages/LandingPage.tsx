import * as React from "react";
import { Link } from "react-router-dom";
import "@/styles/landing.css";
import { MatrixBackground } from "@/components/landing/MatrixBackground";
import { HorusEye } from "@/components/landing/HorusEye";
import { StatusBar } from "@/components/landing/StatusBar";
import { LandingInjectPanel } from "@/components/landing/LandingInjectPanel";
import { useLandingPipeline } from "@/components/landing/useLandingPipeline";
import { useLandingParallax, prefersReducedMotion } from "@/components/landing/useLandingParallax";

const NAV_ITEMS = [
  { label: "Dashboard", to: "/dashboard" },
  { label: "Events", to: "/events" },
  { label: "Alerts", to: "/alerts" },
  { label: "Incidents", to: "/incidents" },
  { label: "Investigation", to: "/investigation" },
  { label: "Threat Lab", to: "/threat-lab" },
];

function pipelineStep(
  stage: string,
  incidents: number,
): { active: number; done: number[] } {
  switch (stage) {
    case "ingesting":
      return { active: 1, done: [0] };
    case "analyzing":
      return { active: 2, done: [0, 1] };
    case "assessed":
      return incidents > 0
        ? { active: 3, done: [0, 1, 2] }
        : { active: 2, done: [0, 1] };
    case "error":
      return { active: 1, done: [0] };
    default:
      return { active: 0, done: [] };
  }
}

const PIPELINE_LABELS = ["Inject", "Analyze", "Understand", "Investigate"];

export function LandingPage() {
  const pipeline = useLandingPipeline();
  useLandingParallax(true);
  const [reducedMotion] = React.useState(() => prefersReducedMotion());
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [pingKey, setPingKey] = React.useState(0);

  const { active, done } = pipelineStep(pipeline.stage, pipeline.result?.assessment.incidents_count ?? 0);

  const systemLabel =
    pipeline.stage === "ingesting"
      ? "SYS · INGESTING"
      : pipeline.stage === "analyzing"
        ? "SYS · ANALYZING"
        : pipeline.stage === "assessed"
          ? `SYS · THREAT ${pipeline.result?.assessment.threat_level ?? ""}`.trim()
          : pipeline.stage === "error"
            ? "SYS · ERROR"
            : "SYS · STANDBY";

  const focusGateway = React.useCallback(() => {
    setMenuOpen(false);
    // The panel pings + focuses itself via the ping key.
    setPingKey((k) => k + 1);
    document.getElementById("hz-gateway")?.scrollIntoView({
      behavior: reducedMotion ? "auto" : "smooth",
      block: "center",
    });
  }, [reducedMotion]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenuOpen(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className={`hz-landing${pipeline.stage !== "idle" ? " hz-has-dataset" : ""}`}>
      <MatrixBackground reducedMotion={reducedMotion} />

      <header className="hz-header">
        <Link className="hz-brand" to="/" aria-label="HORUS — home">
          <svg className="hz-brand-mark" viewBox="0 0 120 70" aria-hidden="true" focusable="false">
            <path d="M10 35 Q60 6 110 35" />
            <path d="M10 35 Q60 64 110 35" />
            <path className="hz-mark-iris" d="M60 23 L72 35 L60 47 L48 35 Z" />
            <path className="hz-mark-tear" d="M60 57 V 66" />
          </svg>
          <span className="hz-brand-name">HORUS</span>
        </Link>

        <nav className="hz-nav" aria-label="Primary">
          {NAV_ITEMS.map((item) => (
            <Link key={item.label} to={item.to}>
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="hz-header-actions">
          <button type="button" className="hz-btn hz-btn-outline hz-btn-sm" onClick={focusGateway}>
            Inject Data
          </button>
          <button
            type="button"
            className="hz-menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="hz-mobile-nav"
            aria-label="Menu"
            onClick={() => setMenuOpen((v) => !v)}
          >
            <span />
            <span />
          </button>
        </div>
      </header>

      <nav className={`hz-mobile-nav${menuOpen ? " is-open" : ""}`} id="hz-mobile-nav" aria-label="Primary">
        {NAV_ITEMS.map((item) => (
          <Link key={item.label} to={item.to} onClick={() => setMenuOpen(false)}>
            {item.label}
          </Link>
        ))}
        <button type="button" className="hz-btn hz-btn-outline" onClick={focusGateway}>
          Inject Data
        </button>
      </nav>

      <main className="hz-hero" id="top">
        <div className="hz-hero-inner">
          <HorusEye reduceMotion={reducedMotion} />

          <h1 className="hz-title">HORUS</h1>
          <p className="hz-subtitle">LOG INTELLIGENCE</p>
          <p className="hz-lede">See what your logs are telling you.</p>

          <div id="hz-gateway" className="hz-gateway">
            <LandingInjectPanel pipeline={pipeline} pingKey={pingKey} />
          </div>

          <ol className="hz-pipeline" aria-label="HORUS workflow">
            {PIPELINE_LABELS.map((label, i) => (
              <li key={label} className={i === active ? "is-active" : done.includes(i) ? "is-done" : ""}>
                <span>{label}</span>
              </li>
            ))}
          </ol>

          <p className="hz-footnote">HORUS — No fake scores. No hallucinations. Deterministic evidence only.</p>
        </div>
      </main>

      <StatusBar systemLabel={systemLabel} />
    </div>
  );
}
