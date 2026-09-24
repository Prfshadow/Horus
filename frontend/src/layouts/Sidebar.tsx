import * as React from "react";
import { NavLink } from "react-router-dom";
import { X, Shield, ScrollText, Siren, Layers, FlaskConical, Telescope, Upload } from "lucide-react";
import { useLocation } from "react-router-dom";
import { HorusMark } from "@/components/console/HorusMark";

const NAV_ITEMS = [
  { label: "Dashboard", to: "/dashboard", icon: Shield },
  { label: "Events", to: "/events", icon: ScrollText },
  { label: "Alerts", to: "/alerts", icon: Siren },
  { label: "Incidents", to: "/incidents", icon: Layers },
  { label: "Inject", to: "/inject", icon: Upload },
  { label: "Threat Lab", to: "/threat-lab", icon: FlaskConical },
  { label: "Investigation", to: "/investigation", icon: Telescope },
];

export function Sidebar({ mobileOpen, onMobileClose }: { mobileOpen: boolean; onMobileClose: () => void }) {
  const location = useLocation();

  // Close the drawer on Escape (AppShell also handles this globally).
  React.useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onMobileClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileOpen, onMobileClose]);

  if (!mobileOpen) return null;

  return (
    <>
      <div
        className="hz-sidebar-overlay fixed inset-0 z-45 lg:hidden"
        onClick={onMobileClose}
        aria-hidden="true"
        data-testid="sidebar-overlay"
      />
      <aside
        className="hz-sidebar fixed inset-y-0 left-0 z-50 flex flex-col w-full max-w-[280px] lg:hidden"
        aria-label="Main navigation"
      >
        <div className="hz-sidebar-header">
          <NavLink to="/" className="hz-brand" aria-label="Go to HORUS home" onClick={onMobileClose}>
            <HorusMark />
            <span className="hz-brand-name">HORUS</span>
            <span className="hz-brand-sub">Log Intelligence</span>
          </NavLink>
          <button
            className="hz-sidebar-close"
            onClick={onMobileClose}
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <nav className="hz-sidebar-nav" aria-label="Primary">
          {NAV_ITEMS.map((item) => {
            const isActive = location.pathname === item.to || (item.to !== "/dashboard" && location.pathname.startsWith(item.to));
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={onMobileClose}
                className={`hz-nav-item${isActive ? " hz-nav-item-active" : ""}`}
                aria-label={item.label}
                aria-current={isActive ? "page" : undefined}
              >
                <item.icon className="h-4 w-4" aria-hidden="true" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
      </aside>
    </>
  );
}