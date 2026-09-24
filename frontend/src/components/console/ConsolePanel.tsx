import * as React from "react";

function Corners() {
  return (
    <>
      <span className="hzc-corner tl" aria-hidden="true" />
      <span className="hzc-corner tr" aria-hidden="true" />
      <span className="hzc-corner bl" aria-hidden="true" />
      <span className="hzc-corner br" aria-hidden="true" />
    </>
  );
}

export function ConsolePanel({ className = "", corners = false, ...props }: React.HTMLAttributes<HTMLDivElement> & { corners?: boolean }) {
  return (
    <div className={`hzc-panel${corners ? " hzc-corners" : ""} ${className}`} {...props}>
      {corners && <Corners />}
      {props.children}
    </div>
  );
}

export function ConsolePanelHead({ className = "", ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`hzc-panel-head ${className}`} {...props} />;
}

export function ConsolePanelTitle({
  className = "",
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={`hzc-panel-title ${className}`} {...props} />;
}

export function ConsolePanelBody({ className = "", ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`hzc-panel-body ${className}`} {...props} />;
}

export function ConsolePageHeader({
  kicker,
  title,
  description,
  actions,
}: {
  kicker: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="hzc-page-head">
      <div>
        <p className="hzc-kicker">{kicker}</p>
        <h1 className="hzc-title">{title}</h1>
        {description && <p className="hzc-subtitle">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
