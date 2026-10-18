import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { api, money } from "../api/client";
import { MandateCard } from "../components/MandateCard";
import { VerdictChip, type Verdict } from "../components/VerdictChip";

export function Dashboard() {
  const { t } = useTranslation();
  const [mandate, setMandate] = useState<any>(null);
  const [balances, setBalances] = useState<any[]>([]);
  const [audit, setAudit] = useState<any[]>([]);

  useEffect(() => {
    api.activeMandate().then(setMandate).catch(() => setMandate({ active: false }));
    api.balances().then((b) => setBalances(b.balances)).catch(() => setBalances([]));
    api.audit().then((a) => setAudit(a.entries.slice(-6).reverse())).catch(() => setAudit([]));
  }, []);

  const plainRule = (rule: any): string => {
    if (rule.type === "category_allow") return `Allowed: ${rule.categories.join(", ")}`;
    if (rule.type === "cap") return `Up to ${money(rule.amount_minor, rule.currency)} per ${rule.scope}`;
    if (rule.type === "escalate_above") return `Over ${money(rule.amount_minor, rule.currency)} needs approval`;
    if (rule.type === "require_registry_match") return "Registry match required";
    return rule.type;
  };

  return (
    <div className="grid gap-6 desktop:grid-cols-[2fr_1fr]">
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold">{t("dash.greeting")}</h1>
        <MandateCard title={t("dash.mandate")} version={mandate?.version} signed={mandate?.active}>
          {mandate?.active ? (
            <ul className="list-disc pl-4">
              {mandate.rules.map((r: any) => (
                <li key={r.id}>{plainRule(r)}</li>
              ))}
            </ul>
          ) : (
            <p>{t("mandate.none")}</p>
          )}
          <Link className="mt-2 inline-block text-seal underline" to="/mandate">
            {t("nav.mandate")} →
          </Link>
        </MandateCard>

        <section>
          <h2 className="mb-2 text-lg font-medium">{t("dash.recent")}</h2>
          {audit.length === 0 ? (
            <p className="text-ink-muted">{t("dash.noPayments")}</p>
          ) : (
            <ul className="divide-y divide-line rounded-panel border border-line bg-surface">
              {audit.map((e) => (
                <li key={e.seq} className="flex items-center justify-between p-3 text-sm">
                  <span className="font-mono text-xs">{e.event_type}</span>
                  <span className="text-ink-muted">{e.ts.slice(0, 10)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <aside className="flex flex-col gap-3">
        <div className="rounded-panel border border-line bg-surface p-4">
          <h2 className="mb-2 text-base font-medium">{t("balances.title")}</h2>
          <ul className="flex flex-col gap-2">
            {balances.map((b) => (
              <li key={b.account_id} className="flex items-center justify-between">
                <span className="text-ink-muted">{b.currency}</span>
                <span className="tnum text-lg font-bold">{money(b.balance_minor, b.currency)}</span>
              </li>
            ))}
          </ul>
        </div>
        <Link to="/pay" className="h-11 rounded-control bg-seal px-5 py-3 text-center text-white">
          {t("pay.upload")}
        </Link>
        <VerdictChip verdict={"ALLOW" as Verdict} />
      </aside>
    </div>
  );
}
