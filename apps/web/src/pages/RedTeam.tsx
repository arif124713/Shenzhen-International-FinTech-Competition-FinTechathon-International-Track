import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";

/** Red-team report page: renders numbers from the report JSON only, never hand-typed (E2E-10). */
export function RedTeam() {
  const { t } = useTranslation();
  const [state, setState] = useState<{ available: boolean; report?: any; message?: string } | null>(null);
  useEffect(() => {
    api.report().then(setState).catch(() => setState({ available: false, message: "unavailable" }));
  }, []);

  if (!state) return <p>…</p>;
  if (!state.available) {
    return (
      <div className="mx-auto max-w-3xl">
        <h1 className="mb-2 text-2xl font-bold">{t("redteam.title")}</h1>
        <p className="text-ink-muted">{state.message}</p>
      </div>
    );
  }

  const r = state.report;
  const systems = Object.entries(r.attacks.systems) as [string, any][];
  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-1 text-2xl font-bold">{t("redteam.title")}</h1>
      <p className="mb-4 text-sm text-ink-muted">
        {t("redteam.reproduce")} Run {r.run_id} · seed {r.seed} · mode {r.mode} · {r.attacks.total} attacks
      </p>
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-line text-left">
            <th className="p-2">System</th>
            <th className="p-2 text-right">Attack success</th>
            <th className="p-2 text-right">Violations</th>
            <th className="p-2 text-right">95% CI</th>
          </tr>
        </thead>
        <tbody>
          {systems.map(([name, d]) => (
            <tr key={name} className="border-b border-line">
              <td className="p-2">{name}</td>
              <td className="tnum p-2 text-right">{(d.asr * 100).toFixed(1)}%</td>
              <td className="tnum p-2 text-right">
                {d.violations}/{d.total}
              </td>
              <td className="tnum p-2 text-right text-ink-muted">
                [{d.ci95[0].toFixed(3)}, {d.ci95[1].toFixed(3)}]
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-3 text-sm">
        False-block rate (benign): {r.false_blocks.blocked}/{r.false_blocks.benign_total} (
        {(r.false_blocks.rate * 100).toFixed(1)}%)
      </p>
      <h2 className="mt-6 mb-2 text-lg font-medium">Failures</h2>
      {r.attacks.failures.length === 0 ? (
        <p className="text-ink-muted">No violations on this run.</p>
      ) : (
        <ul className="list-disc pl-4 text-sm">
          {r.attacks.failures.map((f: any) => (
            <li key={f.case_id} className="font-mono">
              {f.case_id} ({f.stage})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
