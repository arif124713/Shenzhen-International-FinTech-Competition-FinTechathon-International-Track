import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, money } from "../api/client";

export function Balances() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<any[]>([]);
  const [rails, setRails] = useState<any>(null);
  useEffect(() => {
    api.balances().then((b) => setRows(b.balances));
    api.rails("BDT", "USD", 500000).then(setRails).catch(() => setRails(null));
  }, []);

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-4 text-2xl font-bold">{t("balances.title")}</h1>
      <table className="w-full border-collapse">
        <caption className="sr-only">{t("balances.title")}</caption>
        <thead>
          <tr className="border-b border-line text-left">
            <th className="p-2">Account</th>
            <th className="p-2">Currency</th>
            <th className="p-2 text-right">Balance</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((b) => (
            <tr key={b.account_id} className="border-b border-line">
              <td className="p-2 font-mono text-xs">{b.account_id}</td>
              <td className="p-2">{b.currency}</td>
              <td className="tnum p-2 text-right font-bold">{money(b.balance_minor, b.currency)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {rails && (
        <section className="mt-6">
          <h2 className="mb-2 text-lg font-medium">Rail comparison (BDT→USD, simulated)</h2>
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-line text-left">
                <th className="p-2">Rail</th>
                <th className="p-2 text-right">Cost</th>
                <th className="p-2 text-right">Recipient gets</th>
                <th className="p-2 text-right">ETA (h)</th>
              </tr>
            </thead>
            <tbody>
              {rails.ranked.map((q: any) => (
                <tr key={q.rail_id} className={q.rail_id === rails.chosen_rail_id ? "bg-seal-tint" : ""}>
                  <td className="p-2">{q.label}</td>
                  <td className="tnum p-2 text-right">{money(q.total_cost_minor, "USD")}</td>
                  <td className="tnum p-2 text-right">{money(q.recipient_net_minor, "USD")}</td>
                  <td className="tnum p-2 text-right">{q.eta_hours}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-1 text-sm text-ink-muted">{rails.note}</p>
        </section>
      )}
    </div>
  );
}
