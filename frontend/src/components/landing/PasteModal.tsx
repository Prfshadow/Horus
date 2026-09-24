import * as React from "react";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1073741824).toFixed(2)} GB`;
}

interface PasteModalProps {
  open: boolean;
  onClose: () => void;
  onInject: (text: string) => void;
}

/**
 * Accessible paste overlay for log events. One event per line.
 * All content rendered as plain text — never interpreted as HTML.
 */
export function PasteModal({ open, onClose, onInject }: PasteModalProps) {
  const [text, setText] = React.useState("");
  const [invalid, setInvalid] = React.useState(false);
  const [closing, setClosing] = React.useState(false);
  const areaRef = React.useRef<HTMLTextAreaElement>(null);
  const closeTimer = React.useRef(0);

  React.useEffect(() => {
    if (open) {
      setClosing(false);
      // Focus the textarea when the dialog opens.
      const id = window.setTimeout(() => areaRef.current?.focus(), 30);
      return () => window.clearTimeout(id);
    }
    return undefined;
  }, [open ]);

  React.useEffect(() => () => window.clearTimeout(closeTimer.current), []);

  if (!open && !closing) return null;

  const requestClose = () => {
    setClosing(true);
    closeTimer.current = window.setTimeout(() => {
      setClosing(false);
      onClose();
    }, 150);
  };

  const lines = text.split(/\r?\n/).filter((l) => l.trim()).length;
  const bytes = new Blob([text]).size;

  const handleInject = () => {
    if (!text.trim()) {
      setInvalid(true);
      areaRef.current?.focus();
      return;
    }
    const payload = text;
    setText("");
    setInvalid(false);
    onInject(payload);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      requestClose();
    }
  };

  return (
    <div
      className={`hz-modal-backdrop${closing ? " is-closing" : ""}`}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) requestClose();
      }}
    >
      <div
        className="hz-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="hz-paste-title"
        onKeyDown={handleKeyDown}
      >
        <div className="hz-modal-glass">
          <span className="hz-corner tl" aria-hidden="true" />
          <span className="hz-corner tr" aria-hidden="true" />
          <span className="hz-corner bl" aria-hidden="true" />
          <span className="hz-corner br" aria-hidden="true" />

          <div className="hz-modal-head">
            <h2 id="hz-paste-title">Paste log events</h2>
            <button type="button" className="hz-modal-close" onClick={requestClose} aria-label="Close dialog">
              <svg viewBox="0 0 16 16" aria-hidden="true">
                <path d="M4 4l8 8M12 4l-8 8" />
              </svg>
            </button>
          </div>
          <p className="hz-modal-hint">One event per line — JSON objects, JSONL or raw log text.</p>
          <label className="hz-sr-only" htmlFor="hz-paste-area">
            Log events
          </label>
          <textarea
            id="hz-paste-area"
            ref={areaRef}
            value={text}
            onChange={(e) => {
              setText(e.target.value);
              setInvalid(false);
            }}
            spellCheck={false}
            autoComplete="off"
            placeholder='{"ts":"2025-01-14T09:12:03Z","level":"info","service":"auth","msg":"session opened"}'
            aria-invalid={invalid}
          />
          {invalid && <p className="hz-field-error">Nothing to inject — paste at least one event first.</p>}
          <p className="hz-modal-meta" aria-live="polite">
            {lines} {lines === 1 ? "EVENT" : "EVENTS"} &middot; {formatBytes(bytes)}
          </p>
          <div className="hz-modal-actions">
            <button
              type="button"
              className="hz-btn hz-btn-ghost"
              onClick={() => {
                setText("");
                setInvalid(false);
                areaRef.current?.focus();
              }}
            >
              Clear
            </button>
            <button type="button" className="hz-btn hz-btn-primary" onClick={handleInject}>
              Inject Events
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
