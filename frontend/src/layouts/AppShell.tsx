import * as React from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Header } from "@/layouts/Header";
import { Sidebar } from "@/layouts/Sidebar";
import { ConsoleBackground, type ConsoleBackgroundVariant } from "@/components/console/ConsoleBackground";
import "@/styles/console.css";

function backgroundForPath(pathname: string): ConsoleBackgroundVariant {
  if (pathname.startsWith("/events")) return "events";
  if (pathname.startsWith("/alerts")) return "alerts";
  if (pathname.startsWith("/incidents") && !pathname.includes("/investigation")) return "incidents";
  if (pathname.includes("/investigation")) return "investigation";
  if (pathname.startsWith("/threat-lab")) return "investigation";
  if (pathname.startsWith("/inject")) return "dashboard";
  return "dashboard";
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [scrolled, setScrolled] = React.useState(false);
  const { pathname } = useLocation();

  React.useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileOpen(false);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  return (
    <div className="hzc-shell min-h-screen">
      <ConsoleBackground variant={backgroundForPath(pathname)} />
      <div className="hzc-content">
        <Header onMenuToggle={() => setMobileOpen(true)} scrolled={scrolled} />
        <Sidebar mobileOpen={mobileOpen} onMobileClose={() => setMobileOpen(false)} />
        <main className="hzc-main">
          <div className="mx-auto max-w-7xl px-4 lg:px-6 pt-8 pb-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}