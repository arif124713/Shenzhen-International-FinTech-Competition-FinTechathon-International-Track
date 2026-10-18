import { useTranslation } from "react-i18next";

export type Verdict = "ALLOW" | "HOLD" | "ESCALATE" | "DENY";

const SHAPE: Record<Verdict, string> = { ALLOW: "●", HOLD: "⌛", ESCALATE: "▢", DENY: "⬡" };
const COLOR: Record<Verdict, string> = {
  ALLOW: "bg-seal-tint text-seal border-seal",
  HOLD: "bg-hold-tint text-hold border-hold",
  ESCALATE: "bg-hold-tint text-hold border-hold",
  DENY: "bg-deny-tint text-deny border-deny",
};

/** Verdict chip: shape + text + colour together, never colour alone (design.md §3). */
export function VerdictChip({ verdict }: { verdict: Verdict }) {
  const { t } = useTranslation();
  return (
    <span
      role="status"
      className={`inline-flex items-center gap-1 rounded-full border px-3 py-1 text-sm font-medium ${COLOR[verdict]}`}
    >
      <span aria-hidden="true">{SHAPE[verdict]}</span>
      {t(`verdict.${verdict}`)}
    </span>
  );
}
