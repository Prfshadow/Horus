import * as React from "react";

/**
 * SOC status strip: system state, live UTC clock.
 */
export function StatusBar({ systemLabel }: { systemLabel: string }) {
  const [clock, setClock] = React.useState("--:--:--");

  React.useEffect(() => {
    const tick = () => {
      try {
        setClock(new Date().toISOString().slice(11, 19));
      } catch {
        setClock("--:--:--");
      }
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <footer className="hz-statusbar">
      <span className="hz-st-left">
        <i className="hz-st-dot" aria-hidden="true" />
        <span>{systemLabel}</span>
      </span>
      <span className="hz-st-mid">HORUS &middot; DETERMINISTIC EVIDENCE ONLY</span>
      <span className="hz-st-right">UTC {clock}</span>
    </footer>
  );
}
