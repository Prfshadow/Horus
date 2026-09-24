import * as React from "react";
import { NavLink, useLocation } from "react-router-dom";
import { Menu, X, Shield } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { HorusMark } from "@/components/console/HorusMark";
import { useHealth } from "@/hooks/useHealth";

const NAV_ITEMS = [
  { label: "Dashboard", to: "/dashboard", icon: Shield },
  { label: "Events", to: "/events", icon: Shield },
  { label: "Alerts", to: "/alerts", icon: Shield },
  { label: "Incidents", to: "/incidents", icon: Shield },
  { label: "Investigation", to: "/investigation", icon: Shield },
  { label: "Threat Lab", to: "/threat-lab", icon: Shield },
];

function NavIcon({ icon: Icon, active }: { icon: React.ElementType; active: boolean }) {
  return <Icon className={`h-4 w-4 ${active ? "text-emerald-400" : "text-slate-500"}`} aria-hidden="true" />;
}

export function Header({ onMenuToggle, scrolled = false }: { onMenuToggle?: () => void; scrolled?: boolean }) {
  const { data, isLoading, isError } = useHealth();
  const location = useLocation();

  let healthLabel = "Loading";
  let healthClass = "hz-health-warn";
  let dotClass = "hz-health-dot hz-health-warn";

  if (isLoading) {
    healthLabel = "Checking…";
    healthClass = "hz-health-warn";
    dotClass = "hz-health-dot hz-health-warn";
  } else if (isError) {
    healthLabel = "Backend unavailable";
    healthClass = "hz-health-down";
    dotClass = "hz-health-dot hz-health-down";
  } else if (data) {
    if (data.status === "ok" && data.database === "connected") {
      healthLabel = "System operational";
      healthClass = "hz-health-ok";
      dotClass = "hz-health-dot hz-health-ok";
    } else if (data.status === "degraded") {
      healthLabel = "Degraded";
      healthClass = "hz-health-warn";
      dotClass = "hz-health-dot hz-health-warn";
    } else {
      healthLabel = data.status;
      healthClass = "hz-health-warn";
      dotClass = "hz-health-dot hz-health-warn";
    }
  }

  return (
    <header className={`hz-header${scrolled ? " scrolled" : ""}`} role="banner">
      <div className="hz-header-left">
        <Button
          variant="ghost"
          size="icon"
          className="lg:hidden"
          onClick={onMenuToggle}
          aria-label="Toggle navigation"
          aria-expanded="false"
        >
          <Menu className="h-5 w-5" />
        </Button>
        <NavLink to="/" className="hz-brand" aria-label="Go to HORUS home">
          <HorusMark />
          <span className="hz-brand-name">HORUS</span>
          <span className="hz-brand-sub">Log Intelligence</span>
        </NavLink>
      </div>

      <nav className="hz-nav" aria-label="Primary navigation">
        {NAV_ITEMS.map((item) => {
          const isActive = location.pathname === item.to || (item.to !== "/dashboard" && location.pathname.startsWith(item.to));
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive: active }) => `hz-nav-item${active ? " hz-nav-item-active" : ""}`}
              aria-current={isActive ? "page" : undefined}
            >
              <NavIcon icon={item.icon} active={isActive} />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="hz-header-right">
        <div
          className={`hz-health ${healthClass}`}
          role="status"
          aria-live="polite"
          aria-label={`Health: ${healthLabel}`}
        >
          <span className={dotClass} aria-hidden="true" />
          <span className="hidden sm:inline">{healthLabel}</span>
          <span className="sm:hidden">{isError ? "Down" : data?.status === "ok" ? "OK" : "…"}</span>
        </div>
      </div>
    </header>
  );
}