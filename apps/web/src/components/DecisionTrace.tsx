import { useTranslation } from "react-i18next";
import type { TraceStep } from "../api/client";

const CHECKPOINTS = ["document", "registry", "policy", "rail", "result"] as const;
const MARK: Record<string, string> = { pass: "●", hold: "⌛", escalate: "▢", deny: "⬡", skipped: "○" };
const TONE: Record<string, string> = {
  pass: "text-seal",
  hold: "text-hold",
  escalate: "text-hold",
  deny: "text-deny",
  skipped: "text-ink-muted",
};

/** The signature component: a left-to-right track of checkpoints (design.md §1.1, §6.4). */
export function DecisionTrace({ trace, verdict }: { trace: TraceStep[]; verdict: string }) {
  const { t } = useTranslation();
  return (
    <ol className="flex flex-wrap items-start gap-2" aria-label="Decision trace">
      {CHECKPOINTS.map((name, i) => {
        const step = trace.find((s) => s.step === name) ?? trace[i];
        const result = step?.result ?? "skipped";
        return (
          <li key={name} className="flex flex-1 min-w-[120px] flex-col gap-1 border-t-2 border-line pt-2">
            <span className={`flex items-center gap-1 text-sm font-medium ${TONE[result]}`}>
              <span aria-hidden="true">{name === "result" ? MARK[verdict === "ALLOW" ? "pass" : "deny"] : MARK[result]}</span>
              <span className="text-ink">{t(`trace.${name}`)}</span>
            </span>
            <span className="text-xs text-ink-muted">{step?.detail ?? "skipped"}</span>
          </li>
        );
      })}
    </ol>
  );
}
