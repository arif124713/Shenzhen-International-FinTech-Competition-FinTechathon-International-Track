import type { ReactNode } from "react";

/** The Mandate card: notched, perforated edge so a mandate reads as a signed document (design.md §1.2). */
export function MandateCard({ title, version, signed, children }: { title: string; version?: number; signed?: boolean; children: ReactNode }) {
  return (
    <section className="rounded-mandate border border-line bg-surface p-4 shadow-none">
      <header className="mb-2 flex items-center justify-between">
        <h2 className="text-base font-medium">
          {title}
          {version !== undefined && <span className="text-ink-muted"> · v{version}</span>}
        </h2>
        <span className="font-mono text-xs text-seal">{signed ? "Signed ✓" : "Not active"}</span>
      </header>
      <div className="text-sm leading-relaxed">{children}</div>
    </section>
  );
}
